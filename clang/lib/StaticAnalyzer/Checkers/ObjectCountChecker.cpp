//===-- ObjectCountChecker.cpp ------------------------------------*- C++ -*--//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Defines a checker for referencing counting generic objects.
//
// This checker track references counts with functions annotated by
// `object_returns_acquired`, parameters annotated by `object_consumed`, and
// the special function `object_acquire`.
//
// The goal of this checker is to have no false positives but might not be
// exhaustive.
//
//===----------------------------------------------------------------------===//

#include "RetainCountChecker/RetainCountDiagnostics.h"
#include "clang/AST/Attr.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include <iostream>
#include <memory>

using namespace clang;
using namespace ento;

namespace {

class RefCount {
  ///
  /// Reference count for this object.
  ///
  /// Ref count goes up everytime we call acquire, and goes down for
  /// release/autorelease.
  unsigned Cnt{0};

  explicit RefCount(unsigned count) : Cnt(count){};

public:
  /// Helper to create a not owned RefCount.
  ///
  /// This has a reference count of 0.
  LLVM_NODISCARD static RefCount makeUnowned() { return RefCount(0); }

  /// Helper to create a owned RefCount.
  ///
  /// This object has a reference count of 1.
  LLVM_NODISCARD static RefCount makeOwned() { return RefCount(1); }

  /// Create a new RefCount that has the count decremented.
  LLVM_NODISCARD RefCount decrement() const { return RefCount(Cnt - 1); }

  /// Create a new RefCount that has the count increment.
  LLVM_NODISCARD RefCount increment() const { return RefCount(Cnt + 1); }

  /// Get the count for this object.
  LLVM_NODISCARD unsigned getCount() const { return Cnt; }

  bool operator==(const RefCount &Rhs) const { return Cnt == Rhs.getCount(); }

  /// Used to create a hash for this node.
  void Profile(llvm::FoldingSetNodeID &ID) const { ID.AddInteger(Cnt); }
};

class ObjectCountChecker
    : public Checker<check::BeginFunction, check::EndFunction, check::PreCall,
                     check::PostCall, check::Bind, check::DeadSymbols> {
  CallDescription ObjectAcquireFn{"object_acquire"};
  CallDescription ObjectAutoreleaseFn{"object_autorelease"};
  CallDescription ObjectCreateFn{"object_create"};
  CallDescription ObjectReleaseFn{"object_release"};

  /// Report a ref count bug.
  void reportRefCountBug(const retaincountchecker::RefCountBug &D,
                         SymbolRef Sym, const CallEvent *Call,
                         CheckerContext &C) const;

  /// Handle the post call for `object_acquire`.
  void postCallObjectAcquire(const CallEvent &Call, CheckerContext &C) const;

  /// Handle the post call logic for a function that has the
  /// object_returns_acquired attribute.
  void postCallReturnsAcquiredAttr(const CallEvent &Call,
                                   CheckerContext &C) const;

  /// Handle the post call logic for a function that returns a
  /// non-owned object.
  void postCallUnowned(const CallEvent &Call, CheckerContext &C) const;

  /// Handle logic around the return statement.
  /// E.g. Are we returning owned references correctly?
  ExplodedNode *processReturnStatement(const ReturnStmt *RS,
                                       CheckerContext &C) const;

  /// Check if anything is leaking
  void processLeaks(CheckerContext &C, ExplodedNode *Pred) const;

public:
  /// BugTypes below are initialized when we register the checker.
  ///
  /// We reuse this bug type from RetainCountDiagnostics.

  /// Bug to signal when we release something we don't own.
  std::unique_ptr<retaincountchecker::RefCountBug> ReleaseNotOwned{nullptr};
  /// Bug to signal when we return an unowned reference when expected an owned
  /// one.
  std::unique_ptr<retaincountchecker::RefCountBug> ReturnNotOwnedForOwned{
      nullptr};
  /// Bug to signal we are leaking when we return.
  std::unique_ptr<retaincountchecker::RefCountBug> LeakAtReturn{nullptr};
  /// Bug to signal we are leaking within our function.
  std::unique_ptr<retaincountchecker::RefCountBug> LeakWithinFunction{nullptr};

  void checkBeginFunction(CheckerContext &C) const;
  void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal loc, SVal val, const Stmt *S, CheckerContext &C) const;
  void checkDeadSymbols(SymbolReaper &SymReaper, CheckerContext &C) const;
};

} // end anonymous namespace

/// State of object symbol refs to their reference count.
REGISTER_MAP_WITH_PROGRAMSTATE(ObjectRefCountMap, SymbolRef, RefCount)

namespace {

/// Visitor which will remove all visited symbols from the ObjectRefCountMap.
class StopTrackingCallback final : public SymbolVisitor {
  ProgramStateRef State;

public:
  StopTrackingCallback(ProgramStateRef state) : State(std::move(state)) {}
  ProgramStateRef getState() const { return State; }

  bool VisitSymbol(SymbolRef Sym) override {
    State = State->remove<ObjectRefCountMap>(Sym);
    return true;
  }
};

} // namespace

/// Does this function decl have the no analysis annotation.
///
/// This detects if we have the
/// __attribute__((annotate("object_no_anlaysis"))) on our function.  / This
/// is used to bootstrap the object count checker as well as provide an
/// escape hatch for false positives.
LLVM_NODISCARD bool hasNoAnalysisAnnotation(const FunctionDecl *D) {
  for (const auto *Ann : D->specific_attrs<AnnotateAttr>()) {
    if (Ann->getAnnotation() == "object_no_analysis") {
      return true;
    }
  }

  return false;
}

/// Called at the beginning of each function analysis.
///
/// This call will set up the State for all pointer input parameters. If the
/// parameter is tagged with os_consumed we will initialize the State to have a
/// reference count of 1. Otherwise, any other parameter will be initialize to a
/// reference count of 0.
///
/// @note We initialize the State for all pointer input parameters regardless if
/// they are an object or not. This is not optimal but will suffice.
///
/// Non pointer types are not initialized.
void ObjectCountChecker::checkBeginFunction(CheckerContext &C) const {
  // Only handle top-most framed functions. Do not analyzer beginning function.
  if (!C.inTopFrame())
    return;

  const LocationContext *LCtx = C.getLocationContext();
  const Decl *D = LCtx->getDecl();
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(D);

  // Only operate on function declarations and ignore no_analysis function.
  //
  // Since we only care about C, we ignore constructors, destructors, blocks
  // etc. This can be expanded by converting this to an AnyCall.
  if (!FD || hasNoAnalysisAnnotation(FD))
    return;

  ProgramStateRef State = C.getState();
  for (unsigned idx = 0, e = FD->param_size(); idx != e; ++idx) {
    const ParmVarDecl *Param = FD->parameters()[idx];
    QualType Ty = Param->getType();

    // Only continue if it is a single pointer type.
    if (!Ty->isPointerType() || Ty->getPointeeType()->isPointerType())
      continue;

    // Extract the region of memory of the parameter points to then extract a
    // symbol to represent that. This is the key to our object.
    SymbolRef Sym = State->getSVal(State->getRegion(Param, LCtx)).getAsSymbol();

    if (Param->hasAttr<ObjectConsumedAttr>()) {
      // Generate an object whose reference is owned by this function.
      State = State->set<ObjectRefCountMap>(Sym, RefCount::makeOwned());
    } else {
      // Generate an object whose reference is not owned by this function.
      State = State->set<ObjectRefCountMap>(Sym, RefCount::makeUnowned());
    }
  }

  // Add a transition in the graph to be traversed in the output static
  // analysis.
  C.addTransition(State);
}

/// Called before a function invocation to see if references are being
/// consumed. Triggers errors if too many references are consumed.
///
/// This function will look for the `object_consumed` attribute and proceed to
/// consume references. If the object state doesn't exist (e.g. If we accessed
/// it not through the top level parameter but rather indirectly through and
/// object) we do nothing.
void ObjectCountChecker::checkPreCall(const CallEvent &Call,
                                      CheckerContext &C) const {
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
  // Skip all non-functions.
  if (!FD)
    return;

  ProgramStateRef State = C.getState();
  for (unsigned idx = 0, e = FD->param_size(); idx != e; ++idx) {
    const ParmVarDecl *Param = FD->parameters()[idx];

    // If there is no attribute, we just continue. This is done first since the
    // attribute is unlikely to exist making this step skip fast.
    if (!Param->hasAttr<ObjectConsumedAttr>())
      continue;

    // Here we call getAsLocSymbol as the parameter represents a memory
    // location and we want the symbol that represents that location.
    SymbolRef Sym = Call.getArgSVal(idx).getAsLocSymbol();

    // Skip non-pointers to memory regions.
    if (!Sym)
      continue;

    const RefCount *Count = State->get<ObjectRefCountMap>(Sym);
    // Skip those objects that were not already tracked.
    // This helps protect us analyzing global variables and variables within
    // objects.
    if (!Count)
      continue;

    // Check if this is an over-release.
    if (Count->getCount() == 0) {
      reportRefCountBug(*ReleaseNotOwned, Sym, &Call, C);
      return;
    }

    // Update the state to consume a reference.
    State = State->set<ObjectRefCountMap>(Sym, Count->decrement());
  }

  // Update this state transition as a decrement.
  C.addTransition(State);
}
/// Handle the post call logic for `object_acquire`.
///
/// This will increment the reference count. If it is object_acquire and the
/// reference doesn't / exist it will **ignore this reference**. This could
/// happen if it is a global / variable or a variable within a struct.
void ObjectCountChecker::postCallObjectAcquire(const CallEvent &Call,
                                               CheckerContext &C) const {
  SymbolRef Sym = Call.getArgSVal(0).getAsLocSymbol();

  // If this does not resolve to an object this is an invalid usage of the API.
  // E.g. you can pass a integer to object_acquire which will result in this
  // Sym being NULL.
  // TODO: Report incorrect usage of object_acquire?
  if (!Sym)
    return;

  ProgramStateRef State = C.getState();
  const RefCount *Count = State->get<ObjectRefCountMap>(Sym);
  // Not a tracked object. Assume it is global or within a struct and ignore it.
  if (!Count)
    return;

  // Update the state to consume a reference.
  State = State->set<ObjectRefCountMap>(Sym, Count->increment());

  // Update this state transition as a increment.
  C.addTransition(State);
}

/// Handle the post call logic for a function that has the
/// object_returns_acquired attribute.
///
/// We create the state transition for all functions that have this attribute.
void ObjectCountChecker::postCallReturnsAcquiredAttr(const CallEvent &Call,
                                                     CheckerContext &C) const {
  SymbolRef Sym = Call.getReturnValue().getAsSymbol();
  // This should exist or else it is an incorrect usage of the attribute.
  // TODO: Report incorrect use of attribute?
  if (!Sym)
    return;

  ProgramStateRef State = C.getState();

  // Just to verify, this symbol should not be tracked at all (return value from
  // a function).
  const RefCount *Count = State->get<ObjectRefCountMap>(Sym);
  assert(!Count);

  // Create the state as owned.
  State = State->set<ObjectRefCountMap>(Sym, RefCount::makeOwned());

  // Update this state transition as a increment.
  C.addTransition(State);
}

/// Handle the post call logic for a function that returns a
/// non-owned object.
///
/// This will optimistically assume that what is returned is a managed object
/// and create the state to start tracking it.
///
/// This is more expensive computationally but is still correct even for
/// non-managed objects. The reason it is still correct is / this value will
/// start with 0 (not leaked) and only change if the caller CONSUMED it or
/// acquired on it. Therefore, / unless they acquired/consumed on an non-managed
/// object it is already incorrect. That means this will not provide false
/// positives.
void ObjectCountChecker::postCallUnowned(const CallEvent &Call,
                                         CheckerContext &C) const {
  SymbolRef Sym = Call.getReturnValue().getAsSymbol();
  // Non symbolic return values are ignored.
  if (!Sym)
    return;

  ProgramStateRef State = C.getState();
  // Just to verify, this symbol should not be tracked at all (return value from
  // a function).
  const RefCount *Count = State->get<ObjectRefCountMap>(Sym);
  assert(!Count);

  // Create the state as owned.
  State = State->set<ObjectRefCountMap>(Sym, RefCount::makeUnowned());

  // Update this state transition as a increment.
  C.addTransition(State);
}

/// Called after a function invocation to see if references counts need to be
/// incremented (e.g. object_acquire) or if the function returns an object we
/// now need to track.
///
/// Otherwise, it will see if the function returns an acquired reference and
/// start tracking that.
void ObjectCountChecker::checkPostCall(const CallEvent &Call,
                                       CheckerContext &C) const {
  if (Call.isCalled(ObjectAcquireFn)) {
    postCallObjectAcquire(Call, C);
  } else if (Call.getDecl()->hasAttr<ObjectReturnsAcquiredAttr>()) {
    postCallReturnsAcquiredAttr(Call, C);
  } else {
    postCallUnowned(Call, C);
  }
}

/// Whether the memory region should escape and not be tracked.
///
/// We escape when it is assigned something not on the stack or it is assigned
/// to a struct field.
static bool shouldEscape(const MemRegion *MR) {
  // If this is assigned to something not on the stack, we cannot track it
  // anymore.
  if (!MR->hasStackStorage())
    return true;

  const auto *VR = dyn_cast<VarRegion>(MR);
  // If we are assigning this to a struct then stop tracking. (Not 100% this is
  // what this line does.)
  if (!VR)
    return true;

  return false;
}

/// Set escaped counter as soon as we bind this to a struct or global.
///
/// We allow binding to stack variables (we keep tracking that) but as soon as
/// we bind to a struct we cannot track this further.
void ObjectCountChecker::checkBind(SVal loc, SVal val, const Stmt *S,
                                   CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const MemRegion *MR = loc.getAsRegion();

  if (MR && shouldEscape(MR)) {
    // Find all symbols that 'val' references that we are tracking and stop
    // tracking them.
    State = State->scanReachableSymbols<StopTrackingCallback>(val).getState();
    C.addTransition(State);
  }
}

/// Check if anything is leaking.
///
/// This will error if we have anything tracked that has a reference count >0.
void ObjectCountChecker::processLeaks(CheckerContext &C,
                                      ExplodedNode *Pred) const {
  ProgramStateRef State = Pred->getState();
  SmallVector<SymbolRef, 10> Leaked;

  // Loop through all remaining objects.
  for (const auto &I : State->get<ObjectRefCountMap>()) {
    SymbolRef Sym = I.first;
    const RefCount &Count = I.second;

    // Still have lingering reference counts, leaked!
    if (Count.getCount() != 0) {
      Leaked.push_back(Sym);
    }
  }

  // Generate transition to represent leak location.
  // We need to pass the Pred node here since we may have exploded the graph
  // before returning from this step. This will prevent duplicate nodes at the
  // same location.
  ExplodedNode *N = C.addTransition(State, Pred);
  if (!N)
    return;

  for (SymbolRef Sym : Leaked) {
    // Dumb leak detection analysis. We should do something smarter like
    // RetainCountDiagnostics.cpp which walks the allocation chain.
    // We will keep this since at least we see there is a bug and a path.
    // TODO: We need to use walkers to show something useful.
    auto R = std::make_unique<PathSensitiveBugReport>(
        *LeakAtReturn, "Object is potentially being leaked.", N);
    R->markInteresting(Sym);
    C.emitReport(std::move(R));
  }
}

/// Check if we are adhering to the return attribute.
///
/// This will report an error if we are returning something with a reference of
/// 0 to something that has an attribute returned.
///
/// Otherwise, it will consume a reference. The leak detector will determine if
/// this is still leaking.
ExplodedNode *
ObjectCountChecker::processReturnStatement(const ReturnStmt *RS,
                                           CheckerContext &C) const {
  ExplodedNode *Pred = C.getPredecessor();
  const LocationContext *LCtx = C.getLocationContext();
  const Decl *D = LCtx->getDecl();
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(D);

  // Only operate on function declarations and ignore no_analysis function.
  //
  // Since we only care about C, we ignore constructors, destructors, blocks
  // etc. This can be expanded by converting this to an AnyCall.
  if (!FD || hasNoAnalysisAnnotation(FD))
    return Pred;

  // If we don't have the return acquired attribute, we do nothing.
  // If there are any leaks, it will be detected in the leak step.
  if (!FD->hasAttr<ObjectReturnsAcquiredAttr>())
    return Pred;

  const Expr *RetE = RS->getRetValue();
  // If there is no return value and it has the attribute this is an error.
  // TODO: Flag error for bad attributes.
  if (!RetE)
    return Pred;

  ProgramStateRef State = C.getState();
  // Taken from RetainCountChecker.
  // We need to dig down to the symbolic base here because various
  // custom allocators do sometimes return the symbol with an offset.
  SymbolRef Sym = State->getSValAsScalarOrLoc(RetE, C.getLocationContext())
                      .getAsLocSymbol(/*IncludeBaseRegions=*/true);
  if (!Sym)
    return Pred;

  const RefCount *Count = State->get<ObjectRefCountMap>(Sym);
  // If we are not tracking we should return. This will be global variables,
  // variables within structs which we can't track.
  if (!Count)
    return Pred;

  // Check if this is an over-release.
  if (Count->getCount() == 0) {
    reportRefCountBug(*ReturnNotOwnedForOwned, Sym, nullptr, C);
    Pred = C.addTransition(State);
    return Pred;
  }

  // Otherwise, update the state as we are returning and consuming the value.
  State = State->set<ObjectRefCountMap>(Sym, Count->decrement());

  // Update this state transition as a increment.
  Pred = C.addTransition(State);
  return Pred;
}

/// Check if at the end of this function there is some bad state.
///
/// This will check for leaks and if we we are adhering to the return attribute.
void ObjectCountChecker::checkEndFunction(const ReturnStmt *RS,
                                          CheckerContext &C) const {
  // Only check the upper most frame, don't check inline functions.
  if (!C.inTopFrame())
    return;

  ExplodedNode *Pred = processReturnStatement(RS, C);
  processLeaks(C, Pred);
}

/// Check as soon as symbol is dead if it is leaked.
void ObjectCountChecker::checkDeadSymbols(SymbolReaper &SymReaper,
                                          CheckerContext &C) const {
  // TODO: Share this code with processLeaks;
  ProgramStateRef State = C.getState();
  SmallVector<SymbolRef, 10> Leaked;

  // Loop through all remaining objects.
  for (const auto &I : State->get<ObjectRefCountMap>()) {
    SymbolRef Sym = I.first;
    const RefCount &Count = I.second;
    bool IsSymDead = SymReaper.isDead(Sym);

    // Skip non-dead symbols.
    if (!IsSymDead)
      continue;

    // Still have lingering reference counts, leaked!
    if (Count.getCount() != 0) {
      Leaked.push_back(Sym);
    }

    // As a little optimization, remove this from the map.
    if (IsSymDead)
      State = State->remove<ObjectRefCountMap>(Sym);
  }

  // Generate transition to represent leak location.
  ExplodedNode *N = C.addTransition(State);
  if (!N)
    return;

  for (SymbolRef Sym : Leaked) {
    // Dumb leak detection analysis. We should do something smarter like
    // RetainCountDiagnostics.cpp which walks the allocation chain.
    // We will keep this since at least we see there is a bug and a path.
    // TODO: We need to use walkers to show something useful.
    auto R = std::make_unique<PathSensitiveBugReport>(
        *LeakWithinFunction, "Object is potentially being leaked.", N);
    R->markInteresting(Sym);
    C.emitReport(std::move(R));
  }
}

/// Report a ref count bug.
///
/// This is a terminal operation and will stop the analysis going further.
void ObjectCountChecker::reportRefCountBug(
    const retaincountchecker::RefCountBug &D, SymbolRef Sym,
    const CallEvent *Call, CheckerContext &C) const {
  // We reached a bug, stop exploring the path here by generating a sink.
  ExplodedNode *ErrNode = C.generateErrorNode();
  // If we've already reached this node on another path, return.
  if (!ErrNode)
    return;

  // Generate the report.
  auto R = std::make_unique<retaincountchecker::RefCountReport>(
      D, C.getASTContext().getLangOpts(), ErrNode, Sym);
  if (Call) {
    R->addRange(Call->getSourceRange());
  }
  R->markInteresting(Sym);
  C.emitReport(std::move(R));
}

void ento::registerObjectCountChecker(CheckerManager &Mgr) {
  auto *Chk = Mgr.registerChecker<ObjectCountChecker>();
  Chk->ReleaseNotOwned = std::make_unique<retaincountchecker::RefCountBug>(
      Mgr.getCurrentCheckerName(),
      retaincountchecker::RefCountBug::ReleaseNotOwned);

  Chk->ReturnNotOwnedForOwned =
      std::make_unique<retaincountchecker::RefCountBug>(
          Mgr.getCurrentCheckerName(),
          retaincountchecker::RefCountBug::ReturnNotOwnedForOwned);

  Chk->LeakAtReturn = std::make_unique<retaincountchecker::RefCountBug>(
      Mgr.getCurrentCheckerName(),
      retaincountchecker::RefCountBug::LeakAtReturn);

  Chk->LeakWithinFunction = std::make_unique<retaincountchecker::RefCountBug>(
      Mgr.getCurrentCheckerName(),
      retaincountchecker::RefCountBug::LeakWithinFunction);
}

// This checker should be enabled regardless of how language options are set.
bool ento::shouldRegisterObjectCountChecker(const CheckerManager &Mgr) {
  return true;
}
