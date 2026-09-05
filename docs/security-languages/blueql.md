# BlueQL

Analyst hunt language. Parser builds an AST. Compiler never concatenates SQL.

Example:

```text
process.name = "powershell.exe"
AND parent.name IN ("winword.exe", "excel.exe")
```

`;`, `--`, `UNION`, and DML tokens are parse errors.
