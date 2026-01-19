---
title: "Thoughts on shell tools"
date: 2024-02-07T18:41:07+02:00
---
Below a list of points I believe should be handled when writing shell tools.

# Exit Status

Exit status (`exit(0)` or `exit(1)`) is the way for letting the caller know the execution has failed.

Say a you have a script:
{{< highlight python >}}
#!/bin/python
def do_something(args):
     ...

do_something(args)
{{< / highlight >}}


It does not return a value back, it always returns *0*, this prevents being able to check whether the tool has worked or failed.

Using
{{< highlight python >}}       
#!/bin/python

def do_something(args):
    print("error: we failed!")

do_something(args)
{{< / highlight >}}

Doesn't help as well, as you have to grep on the result and check what is happening (given someone hasn't modified the output)

A reasonable tool is therefore returning a **valuable exit status**.

Exit status which is success means zero (0)

Exit status which is failure is nonzero (!0), and can range from 1-255. Different exit statuses can help pinpout the issue easier.

Don't return negative value.

Once you have a tool which return an error code on all cases, you can easily extend the tool or embedd it in CI, Jenkins or any other flow.

{{< highlight bash >}}
#!/bin/bash

if ./our_tool.py; then
    echo "success!"
else
    echo "failure, exit status: $?"
fi
{{< / highlight >}}

# Arguments order

Don't write scripts which are argument order based. 

Ordered based means:
{{< highlight bash >}}
#!/bin/bash
FILE=$1
OUTPUT=$2
EXTRA=$3
# Do something with $FILE, $OUTPUT and $EXTRA
{{< / highlight >}}


This causes the execution of the tool to be extremly uninutative
{{< highlight shell >}}
./script.sh FILE OUTPUT EXTRA
{{< / highlight >}}


Adding things is always at the end, and if a Jenkins job has been modifed, it will look like this: 
{{< highlight shell >}}
if ${OLD_ARGUMENT}; then
    ./script.sh A B C D E F G H I
else
    ./script.sh A B C D E F G L
fi
{{< / highlight >}}


Someone which misses an arugment breaks the entire script and CI.

Basically avoid arguments order and make sure you script is executed like this:  

{{< highlight shell >}}
./script.sh --file FILE --output OUTPUT --extra EXTRA
{{< / highlight >}}

# Arguments naming

Avoid short names for arguments as much as possible, even better, don't even provide such option.

The idea is that calling code must be readable as well, and show the meaning of the execution of the tool itself.

Is this readable?
{{< highlight shell >}}
./script.sh -d ~/A0 -f file.txt -v
{{< / highlight >}}

Or this:
{{< highlight shell >}}
./script.sh --directory ~/A0 --file file.txt --verbose
{{< / highlight >}}

Of course short names allow execution of the tools "faster", but causes a congnitive load on the caller and maintainer later on.

Avoid short names and create EXPLICIT meaning.

# Arguments naming style

Follow regular conventions: https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap12.html#tag_12_01, or https://stackoverflow.com/questions/9725675/is-there-a-standard-format-for-command-line-shell-help-text, do not invent your own convention.

On a personal note, I believe that whoever adds `_` to an argument like `-file_path` is doing it solely to annoy the caller.

# Help

Use regular command line argument parsers as much as possible, as they provide automatic help, avoid parsing argc on your own.

Make sure help is readable and meaningful, and if possible group similar arguments together for readability (like argparse in Python provides - https://docs.python.org/3/library/argparse.html#argument-groups)

# Output results to files

Don't output to a file unless it's specified in a `--file PATH` argument, output directly to `stdout`.

Avoid outputting to a file, generate the output directly to STDOUT, do not use STDERR unless it's for errors.

Say `script.py` is printing JSON file, if it prints to stdout you can: 

{{< highlight shell >}}

./script.py | jq '.[0]'
{{< / highlight >}}

If it's printing to a file, you'd have to:
{{< highlight shell >}}

./script.py | cat ./output.json | jq '.[0]'
{{< / highlight >}}

Of course it doesn't look very critical, but every extra line is causing extra work, and what if the call fails, and previous file is still there? and you don't use return value correctly? it's all a mess which must be handled and causes your tool to not be embedded anywhere at the end.

A tool which prints directly to `stdout` can be checked with `awk` or `jq` or whatever easily. 

# Allow expanding your tools

Just follow this. 

