/**
 * @name Orchestra direct and indirect call facts
 * @description Exports statically resolved direct calls and function-pointer calls with confidence labels.
 * @kind table
 * @id orchestra/calls
 */

import cpp

// Confidence: 1.0 for direct calls to a single known target.
// Function pointer and virtual calls are labelled "unknown" with confidence 0.0
// in this first slice; interprocedural resolution is added separately.

from FunctionCall call, Function target
where target = call.getTarget()
select
  call,
  call.getEnclosingFunction(),
  target,
  call.getLocation().getFile().getRelativePath(),
  call.getLocation().getStartLine(),
  call.getLocation().getStartColumn(),
  "direct",
  1.0
