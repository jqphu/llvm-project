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

#include "clang/AST/Attr.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"

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

  /// Get the count for this object.
  LLVM_NODISCARD unsigned getCount() const { return Cnt; }

  bool operator==(const RefCount &Rhs) const { return Cnt == Rhs.getCount(); }

  /// Used to create a hash for this node.
  void Profile(llvm::FoldingSetNodeID &ID) const { ID.AddInteger(Cnt); }
};

class ObjectCountChecker : public Checker<check::BeginFunction> {
  CallDescription ObjectAcquireFn{"object_acquire"};
  CallDescription ObjectAutoreleaseFn{"object_autorelease"};
  CallDescription ObjectCreateFn{"object_create"};
  CallDescription ObjectReleaseFn{"object_release"};

public:
  void checkBeginFunction(CheckerContext &C) const;
};

} // end anonymous namespace

/// State of object symbol refs to their reference count.
REGISTER_MAP_WITH_PROGRAMSTATE(ObjectRefCountMap, SymbolRef, RefCount)

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

void ento::registerObjectCountChecker(CheckerManager &mgr) {
  mgr.registerChecker<ObjectCountChecker>();
}

// This checker should be enabled regardless of how language options are set.
bool ento::shouldRegisterObjectCountChecker(const CheckerManager &mgr) {
  return true;
}
