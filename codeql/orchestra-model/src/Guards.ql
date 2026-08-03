/**
 * @name Orchestra binary guard facts
 * @description Exports if-statement predicates for the first source-to-runtime mapping milestone.
 * @kind table
 * @id orchestra/guards
 */

import cpp

from IfStmt statement, Expr guard
where guard = statement.getCondition()
select
  guard,
  guard.getEnclosingFunction(),
  guard.getLocation().getFile().getRelativePath(),
  guard.getLocation().getStartLine(),
  guard.getLocation().getStartColumn(),
  guard.getLocation().getEndLine(),
  guard.getLocation().getEndColumn(),
  guard.toString()
