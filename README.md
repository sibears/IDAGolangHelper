# IDAGolangHelper
Set of IDA Pro scripts for parsing GoLang types information stored in compiled binary


This is update for https://gitlab.com/zaytsevgu/GoUtils2.0

Differences:
  1. Add support for go1.8 and go1.9, go1.10 (well actually it seems no difference from go1.9)
  2. Automatically add user-defined types to IDA. (Can be checked in Shift+f9 view)
  3. Add some not very advanced string recognition. You can press Shift+S to process current function


https://2016.zeronights.ru/wp-content/uploads/2016/12/GO_Zaytsev.pdf - My presentation about Golang reversing
