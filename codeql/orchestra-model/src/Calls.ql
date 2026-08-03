/**
 * @name Orchestra direct call facts
 * @description Exports statically resolved direct calls. Indirect-call modeling is added separately with confidence labels.
 * @kind table
 * @id orchestra/calls
 */

import cpp

from FunctionCall call, Function target
where target = call.getTarget()
select
  call,
  call.getEnclosingFunction(),
  target,
  call.getLocation().getFile().getRelativePath(),
  call.getLocation().getStartLine(),
  call.getLocation().getStartColumn(),
  "direct"
