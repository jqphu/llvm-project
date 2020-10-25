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

#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

using namespace clang;
using namespace ento;

namespace {
class ObjectCountChecker : public Checker<check::BeginFunction> {
public:
  ObjectCountChecker();

  void checkBeginFunction(CheckerContext &C) const;
};

} // end anonymous namespace

ObjectCountChecker::ObjectCountChecker() {}

void ObjectCountChecker::checkBeginFunction(
    CheckerContext &checkerContext) const {
  // TODO: Fill in.
}

void ento::registerObjectCountChecker(CheckerManager &mgr) {
  mgr.registerChecker<ObjectCountChecker>();
}

// This checker should be enabled regardless of how language options are set.
bool ento::shouldRegisterObjectCountChecker(const CheckerManager &mgr) {
  return true;
}
