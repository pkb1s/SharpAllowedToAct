# SharpAllowedToAct

## Description ##

A C# implementation of a computer object takeover through Resource-Based Constrained Delegation (msDS-AllowedToActOnBehalfOfOtherIdentity) based on the [research](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html) by [@elad_shamir](https://twitter.com/elad_shamir).
Credits also to [@harmj0y](https://twitter.com/harmj0y) for his [blog post](http://www.harmj0y.net/blog/activedirectory/a-case-study-in-wagging-the-dog-computer-takeover/) and to [@kevin_robertson](https://twitter.com/kevin_robertson) as I relied on the code for his [Powermad](https://github.com/Kevin-Robertson/Powermad) tool.

## Compile Instructions ## 
SharpAllowedToAct has been built against .NET 3.5 and is compatible with Visual Studio 2017. Simply open the solution file and build the project.

CommandLineParser has been used in order to parse the arguments. This package will need to be installed using the following command:

`Install-Package CommandLineParser -Version 1.9.3.15`

After compiling the project simply merge the .exe and the CommandLine.dll into one executable file:

`ILMerge.exe /out:C:\SharpAllowedToAct.exe C:\Release\SharpAllowedToAct.exe C:\Release\CommandLine.dll`
