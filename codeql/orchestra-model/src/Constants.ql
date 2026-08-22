/**
 * @name Orchestra predicate constant facts
 * @description Exports integer and string constants found inside guard predicates, for dictionary token generation.
 * @kind table
 * @id orchestra/constants
 */

import cpp

// Collect constant literals that appear inside if-guard conditions.
// These are raw evidence for dictionary tokens; the model builder decides
// which to emit and how to format them per engine.

from IfStmt statement, Expr guard, Literal literal
where
  guard = statement.getCondition() and
  literal = guard.getAChild*() and
  (
    literal instanceof HexLiteral
    or
    literal instanceof OctalLiteral
    or
    literal instanceof StringLiteral
    or
    literal instanceof CharLiteral
  )
select
  literal,
  guard.getEnclosingFunction(),
  literal.getLocation().getFile().getRelativePath(),
  literal.getLocation().getStartLine(),
  literal.getLocation().getStartColumn(),
  literal.toString(),
  literal.getUnderlyingType().toString()
