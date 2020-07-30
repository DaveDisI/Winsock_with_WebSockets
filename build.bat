"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build"\vcvarsall x64 && ^
cl winsock.cpp /Zi /Fewinsock /link Ws2_32.lib
