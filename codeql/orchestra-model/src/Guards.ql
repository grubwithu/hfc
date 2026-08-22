/**
 * @name Orchestra binary guard facts
 * @description Exports if/loop/switch/conditional-expression guards with raw predicate features for source-to-runtime mapping.
 * @kind table
 * @id orchestra/guards
 */

import cpp

// Guard kind: the first slice supports binary if-guards.
string guardKind(IfStmt s) { result = "if" }

// Determine if an expression is a literal constant.
predicate isConstantLiteral(Expr e) {
  e instanceof HexLiteral
  or
  e instanceof OctalLiteral
  or
  e instanceof StringLiteral
  or
  e instanceof CharLiteral
}

// Operator string for binary operations, or "none" for non-binary guards.
string guardOperator(Expr guard) {
  guard instanceof BinaryOperation and
  result = guard.(BinaryOperation).getOperator()
  or
  not guard instanceof BinaryOperation and
  result = "none"
}

// 1 if the guard sub-tree contains a constant literal, 0 otherwise.
int hasConstant(Expr guard) {
  exists(Expr sub | sub = guard.getAChild*() and isConstantLiteral(sub)) and
  result = 1
  or
  not exists(Expr sub | sub = guard.getAChild*() and isConstantLiteral(sub)) and
  result = 0
}

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
  guard.toString(),
  guardKind(statement),
  guard.getUnderlyingType().toString(),
  guardOperator(guard),
  hasConstant(guard)
