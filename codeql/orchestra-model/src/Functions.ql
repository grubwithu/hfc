/**
 * @name Orchestra function facts
 * @description Exports source functions for the immutable Program Model.
 * @kind table
 * @id orchestra/functions
 */

import cpp

from Function f
where not f.isCompilerGenerated()
select
  f,
  f.getQualifiedName(),
  f.getLocation().getFile().getRelativePath(),
  f.getLocation().getStartLine(),
  f.getLocation().getStartColumn(),
  f.getLocation().getEndLine(),
  f.getLocation().getEndColumn()
