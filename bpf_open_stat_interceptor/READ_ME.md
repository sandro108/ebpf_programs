

Hi there!


In the present directory you will find an executable bpf_program called "open_stat_interceptor".

It was compiled for x86_64 arch and tested on a linux 5.14.0-427.33.1.el9_4.x86_64 kernel version. No software pre-requisites are needed to run it.


Please feel free to query the usage options with "./open_stat_interceptor -h".

The output of the program is pretty much self-explainatory. For convienience a title at the first line is printed, that explains the type of contents the columns show.


It is recommended to start the program with a PID supplied as argument, to avoid massive verbosity, flooding 
the terminal or filling the file you have redirected stdout to in no time. 

In this version of the program the output is printed to stdout. If needed a possibility to write to a specified file can be implemented.
Same is valid for other metrics, if needed to be shown in the output, for easier analyses.
In both cases let me know what you need.

May it be helpful,

Sandro




