# Notes

What I wrote down while learning YARA, before writing the rules in this repo. Every example rule in these notes compiles with YARA 4.5.

1. [Syntax and conditions](01-syntax-and-conditions.md): strings, modifiers, hex patterns, counting, offsets, `of` and `for..of`
2. [The pe, math and dotnet modules](02-pe-math-dotnet-modules.md): imports, sections, entropy, .NET metadata streams, first practice rules
3. [yara-python and pefile](03-yara-python-and-pefile.md): compiling and matching from Python, reading PE data, a first scanner

The analysis that used to be days 4 and 5 now lives with its rules in [rules/agenttesla](../rules/agenttesla/) and [rules/asyncrat](../rules/asyncrat/).
