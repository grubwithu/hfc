/**
 * @name Orchestra function facts
 * @description Exports source functions with harness reachability for the immutable Program Model.
 * @kind table
 * @id orchestra/functions
 */

import cpp

// The OSS-Fuzz harness entry point convention.
predicate isHarnessEntry(Function f) {
  f.getName() = "LLVMFuzzerTestOneInput"
}

// A function is reachable from the harness if there is a static call chain
// from LLVMFuzzerTestOneInput to it (transitive closure over direct calls).
predicate reachableFromHarness(Function target) {
  exists(Function entry, FunctionCall call |
    isHarnessEntry(entry) and
    call.getEnclosingFunction() = entry and
    call.getTarget() = target
  )
  or
  exists(FunctionCall call |
    reachableFromHarness(call.getEnclosingFunction()) and
    call.getTarget() = target
  )
}

// Harness reachability flag: 1 if the function is the entry or reachable
// from it, 0 otherwise.
int harnessReachable(Function f) {
  (isHarnessEntry(f) or reachableFromHarness(f)) and result = 1
  or
  not (isHarnessEntry(f) or reachableFromHarness(f)) and result = 0
}

// C linkage flag.
int hasCLinkageFlag(Function f) {
  f.hasCLinkage() and result = 1
  or
  not f.hasCLinkage() and result = 0
}

from Function f
where not f.isCompilerGenerated()
select
  f,
  f.getQualifiedName(),
  f.getLocation().getFile().getRelativePath(),
  f.getLocation().getStartLine(),
  f.getLocation().getStartColumn(),
  f.getLocation().getEndLine(),
  f.getLocation().getEndColumn(),
  harnessReachable(f),
  hasCLinkageFlag(f)
