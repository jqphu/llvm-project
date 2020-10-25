//===-- ObjectCountChecker.cpp -----------------------------------------*- C++ -*--//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Defines a checker for proper use of fopen/fclose APIs.
//   - If a file has been closed with fclose, it should not be accessed again.
//   Accessing a closed file results in undefined behavior.
//   - If a file was opened with fopen, it must be closed with fclose before
//   the execution ends. Failing to do so results in a resource leak.
//
//===----------------------------------------------------------------------===//

#include "clang/Analysis/AnyCall.h"
#include "clang/AST/Attr.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include <utility>
#include <cstddef>
#include <iostream>

using namespace clang;
using namespace ento;

namespace {
typedef SmallVector<SymbolRef, 2> SymbolVector;
using RefCount = int;

class ObjectState {
private:
  RefCount refCount_{0};
  bool escaped_{false};
  explicit ObjectState(RefCount refCount, bool escaped): refCount_(refCount), escaped_(escaped) { }

public:
  static ObjectState empty() {
    return ObjectState(0, false);
  }

  // Object in Created state.
  static ObjectState created() {
    return ObjectState(1, false);
  }

  LLVM_NODISCARD bool hasEscaped() const {
    return escaped_;
  }

  bool operator==(const ObjectState &state) const {
    return state.refCount_ == refCount_;
  }

  void Profile(llvm::FoldingSetNodeID &ID) const {
    ID.AddInteger(refCount_);
  }

  LLVM_NODISCARD RefCount refCount() const { return refCount_; }

  // Returns the ref count.
  static ObjectState incrementCount(const ObjectState& object) {
    return ObjectState(object.refCount_ + 1, object.escaped_);
  }

  static ObjectState decrementCount(const ObjectState& object) {
    return ObjectState(object.refCount_ - 1, object.escaped_);
  }

  static ObjectState escaped(const ObjectState& object) {
    return ObjectState(object.refCount_, true);
  }
};

class ObjectCountChecker : public Checker<check::PostCall,
                                           check::PreCall,
                                           check::DeadSymbols,
                                           check::EndFunction,
                                           check::BeginFunction,
                                           check::PointerEscape
                                           > {
  CallDescription ObjectAcquireFn;

  std::unique_ptr<BugType> DoubleCloseBugType;
  std::unique_ptr<BugType> LeakBugType;

  void reportDoubleClose(SymbolRef FileDescSym,
                         const CallEvent &Call,
                         CheckerContext &C) const;

  void reportLeaks(ArrayRef<SymbolRef> LeakedStreams, CheckerContext &C,
                   ExplodedNode *ErrNode) const;


public:
  ObjectCountChecker();

  /// Process ObjectCreate.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

  /// Process ObjectRelease.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;


  // Check if we leaked!
  void checkDeadSymbols(SymbolReaper &SymReaper, CheckerContext &C) const;
  void checkBeginFunction(CheckerContext &Ctx) const;
  void checkEndFunction(const ReturnStmt *RS, CheckerContext &Ctx) const;

  /// Stop tracking addresses which escape.
  ProgramStateRef checkPointerEscape(ProgramStateRef State,
                                    const InvalidatedSymbols &Escaped,
                                    const CallEvent *Call,
                                    PointerEscapeKind Kind) const;

};

} // end anonymous namespace

/// The state of the checker is a map from tracked stream symbols to their
/// state. Let's store it in the ProgramState.
REGISTER_MAP_WITH_PROGRAMSTATE(ObjectMap, SymbolRef, ObjectState)

namespace {
class StopTrackingCallback final : public SymbolVisitor {
  ProgramStateRef state;
public:
  StopTrackingCallback(ProgramStateRef st) : state(std::move(st)) {}
  ProgramStateRef getState() const { return state; }

  bool VisitSymbol(SymbolRef sym) override {
    state = state->remove<ObjectMap>(sym);
    return true;
  }
};
} // end anonymous namespace

ObjectCountChecker::ObjectCountChecker()
    : ObjectAcquireFn("object_acquire") {
  // Initialize the bug types.
  DoubleCloseBugType.reset(
      new BugType(this, "Double fclose", "Unix Object API Error"));

  // Sinks are higher importance bugs as well as calls to assert() or exit(0).
  LeakBugType.reset(
      new BugType(this, "Resource Leak", "Unix Stream API Error",
                  /*SuppressOnSink=*/true));
}


void ObjectCountChecker::checkBeginFunction(CheckerContext &checkerContext) const {
  if (!checkerContext.inTopFrame())
    return;

  const LocationContext *locationContext = checkerContext.getLocationContext();
  const Decl *D = locationContext->getDecl();
  auto anyCall = AnyCall::forDecl(D);
  if(!anyCall)
    return;

  ProgramStateRef state = checkerContext.getState();

  for (const ParmVarDecl *pvd : anyCall->parameters()) {
    Loc paramLocation = state->getLValue(pvd, locationContext);
    // We never consider top-level function parameters undefined.
    SymbolRef object =
        state->getSVal(paramLocation).castAs<DefinedOrUnknownSVal>().getAsSymbol();

    std::cout << "Decl has attr: " << pvd->hasAttr<ObjectConsumedAttr>() << std::endl;
    const ObjectState *objectState = state->get<ObjectMap>(object);

    std::cout << "Setting object: " << object << std::endl;

    if(objectState != nullptr) {
      std::cout << "State already created, exiting." << std::endl;
      continue;
    }

    // Is consumed attribute.
    if(pvd->hasAttr<ObjectConsumedAttr>()) {
      // Generate the next transition (an edge in the exploded graph).

      std::cout << "Has consumed attribute!" << std::endl;
      // Generate the next transition, reference count has dropped.
      state = state->set<ObjectMap>(object, ObjectState::created());
    } else {
      std::cout << "No consumed, creating empty" << std::endl;
      // Generate the next transition, reference count has dropped.
      state = state->set<ObjectMap>(object, ObjectState::empty());
    }

    // Add transition and exit!
    checkerContext.addTransition(state);
  }
}

/**
 * Check after calling object create.
 */
void ObjectCountChecker::checkPostCall(const CallEvent &call,
                                        CheckerContext &checkerContext) const {
  bool hasAcquiredAttr = call.getDecl()->hasAttr<ObjectReturnAcquiredAttr>();

  // Function must be object_create.
  if (!hasAcquiredAttr)
    return;

  // Get the symbolic value corresponding to the object.
  SymbolRef object = call.getReturnValue().getAsSymbol();
  if(object != nullptr) {
    std::cout << "ERROR: Object should not exist.\n";
    return;
  }

  std::cout << "Object is: " << object << std::endl;

  // Generate the next transition (an edge in the exploded graph).
  ProgramStateRef state = checkerContext.getState();

  std::cout << "State being set to created";

  state = state->set<ObjectMap>(object, ObjectState::created());

  // State transition added!
  checkerContext.addTransition(state);
}

/**
 * Check before calling release.
 */
void ObjectCountChecker::checkPreCall(const CallEvent &call,
                                       CheckerContext &checkerContext) const {
  std::cout <<"Pre call\n";
  ProgramStateRef state = checkerContext.getState();
  if(call.isCalled(ObjectAcquireFn)) {
  std::cout <<"Acquire called\n";
      // Get the symbolic value corresponding to the object.
      SymbolRef object = call.getArgSVal(0).getAsSymbol();
      if (!object) {
        std::cout << "Could not get symbolic value for object" << std::endl;
        return;
      }
      const ObjectState *objectState = state->get<ObjectMap>(object);

      // Object state might not exist, if this is a global or smth.
      if(objectState == nullptr) {
        std::cout << "No state transition since no state was found!" << std::endl;
        return;

        // Create a state with refcount of 0!
        // state = state->set<ObjectMap>(object, ObjectState::empty());
        // objectState = state->get<ObjectMap>(object);
      }

      // We definitely don't have the ref counts. Stop this.
      if (objectState->refCount() < 0) {
        reportDoubleClose(object, call, checkerContext);
        return;
      }

      // Generate the next transition, reference count has dropped.
      state = state->set<ObjectMap>(object, ObjectState::incrementCount(*objectState));

    } else {

      std::cout <<"Not acquire\n";


    const FunctionDecl *FuncDecl = dyn_cast_or_null<FunctionDecl>(call.getDecl());

    for (unsigned Arg = 0; Arg < call.getNumArgs(); ++Arg) {

      // TODO: ??
      if (Arg >= FuncDecl->getNumParams())
        break;

      const ParmVarDecl *pvd = FuncDecl->getParamDecl(Arg);
      SymbolRef object = call.getArgSVal(Arg).getAsSymbol();
      if (object == nullptr){
        std::cout << "Not a valid object, continuing\n";
        continue;
      }

      std::cout << "PAram object is: " << object;

      const ObjectState *objectState = state->get<ObjectMap>(object);
      if(objectState == nullptr) {
        std::cout << "State doesn't exist, ignoring." << std::endl;
        continue;
      }

      std::cout << "Decl has attr: " << pvd->hasAttr<ObjectConsumedAttr>() << std::endl;
      // Is consumed attribute.
      if(pvd->hasAttr<ObjectConsumedAttr>()) {
        // We have 0 reference counts when we are calling this function!
        if (objectState->refCount() == 0) {
          reportDoubleClose(object, call, checkerContext);
          return;
        }


        // Generate the next transition (an edge in the exploded graph).
        std::cout << "Has consumed attribute!" << std::endl;
        // Generate the next transition, reference count has dropped.
        state = state->set<ObjectMap>(object, ObjectState::decrementCount(*objectState));
      }
    }
  }

  checkerContext.addTransition(state);
}

static bool isLeaked(SymbolRef Sym, const ObjectState &SS,
                     bool IsSymDead, ProgramStateRef State) {
  if (IsSymDead && !SS.hasEscaped() && SS.refCount() > 0) {
    std::cout << "Leaking SYM: " << Sym << "refcount is: " << SS.refCount() << std::endl;
    // If a symbol is NULL, assume that fopen failed on this path.
    // A symbol should only be considered leaked if it is non-null.
    ConstraintManager &CMgr = State->getConstraintManager();
    ConditionTruthVal OpenFailed = CMgr.isNull(State, Sym);
    return !OpenFailed.isConstrainedTrue();
  }
  return false;
}

// If the pointer we are tracking escaped, do not track the symbol as
// we cannot reason about it anymore.
ProgramStateRef
ObjectCountChecker::checkPointerEscape(ProgramStateRef State,
                                        const InvalidatedSymbols &Escaped,
                                        const CallEvent *Call,
                                        PointerEscapeKind Kind) const {
  // Passing object to a function does not count as an escape.
  if (Kind == PSK_DirectEscapeOnCall) {
    std::cout << "Direct escape, returning." << std::endl;
    return State;
  }

  for (InvalidatedSymbols::const_iterator I = Escaped.begin(),
                                          E = Escaped.end();
                                          I != E; ++I) {
    SymbolRef Sym = *I;

    // The symbol escaped. Optimistically, assume that the corresponding file
    // handle will be closed somewhere else.
    const ObjectState *objectState = State->get<ObjectMap>(Sym);
    if(objectState != nullptr) {
      auto state = ObjectState::escaped(*objectState);
      std::cout << "State: " << &*State;
      std::cout << "Escaped object: " << Sym << "stored state is escaped: " <<
        state.hasEscaped() <<  " has a refcount of: " <<
        state.refCount() << std::endl;
      // TODO: Make this into an escaped state instead of removing it.
      // State = State->set<ObjectMap>(Sym, state);
      State = State->remove<ObjectMap>(Sym);
    }
  }

  std::cout << "Done!" << std::endl;

  return State;
}

/**
 * Check all symbols that are no longer accessible.
 */
void ObjectCountChecker::checkDeadSymbols(SymbolReaper &SymReaper,
                                           CheckerContext &C) const {
  std::cout << "Checking dead symbols\n";
  ProgramStateRef State = C.getState();
  SymbolVector LeakedObjects;
  ObjectMapTy TrackedObjects = State->get<ObjectMap>();
  for (ObjectMapTy::iterator I = TrackedObjects.begin(),
                             E = TrackedObjects.end(); I != E; ++I) {
    SymbolRef Sym = I->first;
    bool IsSymDead = SymReaper.isDead(Sym);

    // Collect leaked symbols.
    if (isLeaked(Sym, I->second, IsSymDead, State))
      LeakedObjects.push_back(Sym);

    // Remove the dead symbol from the streams map.
    if (IsSymDead)
      State = State->remove<ObjectMap>(Sym);
  }

  ExplodedNode *N = C.generateNonFatalErrorNode(State);
  if (!N)
    return;
  reportLeaks(LeakedObjects, C, N);
}


/**
 * Check at the very end, if anything was leaked.
 *
 * TODO: Check return statement if it is marked return acquired then we need to return a reference.
 */
void ObjectCountChecker::checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const {
  if (!C.inTopFrame())
    return;
  SymbolRef object = nullptr;
  std::cout << "Checking end func symbols\n";
  if(RS) {
    const Expr* retVal = RS->getRetValue();
    if(retVal != nullptr) {
      ProgramStateRef state = C.getState();
      // We need to dig down to the symbolic base here because various
      // custom allocators do sometimes return the symbol with an offset.
      object = state->getSValAsScalarOrLoc(retVal, C.getLocationContext())
        .getAsLocSymbol(/*IncludeBaseRegions=*/true);
    }
  }


  ProgramStateRef State = C.getState();
  SymbolVector LeakedObjects;
  ObjectMapTy TrackedObjects = State->get<ObjectMap>();
  for (ObjectMapTy::iterator I = TrackedObjects.begin(),
                             E = TrackedObjects.end(); I != E; ++I) {
    SymbolRef Sym = I->first;

    // Handle return value at the end.
    if(Sym == object) {
      continue;
    }

    // Collect leaked symbols.
    if (isLeaked(Sym, I->second, true, State))
      LeakedObjects.push_back(Sym);
  }

  const LocationContext *locationContext = C.getLocationContext();
  const Decl *D = locationContext->getDecl();
  auto funcCall = dyn_cast<FunctionDecl>(D);
  if(!funcCall)
    return;

  if(funcCall->hasAttr<ObjectReturnAcquiredAttr>()) {
    if(object == nullptr) {
      std::cout << "BAD object\n";
        return;
    }
    const ObjectState *objectState = State->get<ObjectMap>(object);
    if(objectState == nullptr) {
      std::cout << "BAD NULL\n";
      return;
    }
    if(!objectState->hasEscaped() && objectState->refCount() != 1) {
      LeakedObjects.push_back(object);
    }
  }

  ExplodedNode *N = C.generateNonFatalErrorNode(State);
  if (!N)
    return;
  reportLeaks(LeakedObjects, C, N);

}

void ObjectCountChecker::reportLeaks(ArrayRef<SymbolRef> LeakedObjects,
                                      CheckerContext &C,
                                      ExplodedNode *ErrNode) const {
  // Attach bug reports to the leak node.
  for (SymbolRef LeakedObject : LeakedObjects) {
    std::cout << "Object: " << LeakedObject << " has been leaked!" << std::endl;
    auto R = std::make_unique<PathSensitiveBugReport>(
        *LeakBugType, "Object is being leaked here.",
        ErrNode);
    R->markInteresting(LeakedObject);
    C.emitReport(std::move(R));
  }
}

void ObjectCountChecker::reportDoubleClose(SymbolRef FileDescSym,
                                            const CallEvent &Call,
                                            CheckerContext &C) const {
  // We reached a bug, stop exploring the path here by generating a sink.
  ExplodedNode *ErrNode = C.generateErrorNode();
  // If we've already reached this node on another path, return.
  if (!ErrNode)
    return;

  // Generate the report.
  auto R = std::make_unique<PathSensitiveBugReport>(
      *DoubleCloseBugType, "Releasing an already released object", ErrNode);
  R->addRange(Call.getSourceRange());
  R->markInteresting(FileDescSym);
  C.emitReport(std::move(R));
}

void ento::registerObjectCountChecker(CheckerManager &mgr) {
  mgr.registerChecker<ObjectCountChecker>();
}

// This checker should be enabled regardless of how language options are set.
bool ento::shouldRegisterObjectCountChecker(const CheckerManager &mgr) {
  return true;
}
