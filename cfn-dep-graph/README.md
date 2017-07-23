# CloudFormation Depedency Sorter

This takes a YAML CloudFormation template on stdin, and produces a topologically sorted list of dependencies (in the form of `A B` where `A` depends on `B`), suitable for piping into `tsort`.

This is useful for identifying circular dependencies in large CloudFormation templates.
