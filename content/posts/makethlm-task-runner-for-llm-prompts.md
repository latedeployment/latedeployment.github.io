---
title: "makethlm - LLM builder"
date: 2026-02-13T14:00:00
tags: ["python", "llm"]
---

A small tool I built is [makethlm](https://github.com/latedeployment/makethlm), a command-line task runner in the tradition of Make and Just, but where the task body is natural language executed by an LLM. 

## Why

Because why not? :) 

LLMs can be used in building as well, so why not? Make and Just are great for defining workflows, but every step has to be a shell command. You can ask LLM to generate code, review diffs, explain failures, or write configs.

Write a `Promptfile`, and each task is a mix of LLM prompts and shell commands (executed directly). Dependencies, variables, and arguments work the way you'd expect from Just (most of it...)

## Quick example

```makefile
# Promptfile

project := "my-web-app"

llm claude [model=sonnet]

task build:
    !mkdir -p dist
    check if src/ has changed since the last build.
    if so, compile the TypeScript and bundle with esbuild.

task test: build
    !npm test
    if any tests failed, explain the root cause and suggest a fix.

task deploy(target, port="8080"): build test
    !systemctl restart {{project}}
    verify {{project}} is running on {{target}} port {{port}}.
```

```bash
makethlm deploy staging       # runs build -> test -> deploy
makethlm --dry-run deploy     # preview without executing
makethlm --list               # list all tasks
```

## Features I like

**Functions** let you define reusable prompt templates and inject them into tasks with `@use`:

```makefile
fn security_review:
    Review the code for security vulnerabilities.
    Check for SQL injection, XSS, command injection, path traversal.

task review:
    @use security_review
    Focus on the git diff for the current PR.
```

**Docker blocks** describe images in plain English - the LLM generates the Dockerfile, `makethlm` builds it:

```makefile
docker api-server [tag=latest]:
    A Python 3.11 slim image.
    Install requirements.txt with pip, no cache.
    Copy app/ to /app. Expose port 8080.
    Run with gunicorn, 4 workers.
```

**SSH host inventory** lets you run tasks on remote hosts, like in `ansible`:

```makefile
hosts web [user=deploy]:
    web1.prod.internal
    web2.prod.internal

task deploy [on=web]: build
    !systemctl restart {{project}}
    verify the service is healthy
```

**Multi-LLM routing** -- define multiple providers and pick one per task:

```makefile
llm claude [model=opus]
llm openai [model=gpt-4]

task review [llm=openai]:
    review the code
```

It also supports Just-compatible features like `set dotenv-load`, conditional expressions, string functions, variadic arguments, and OS-specific tasks (`[linux]`, `[macos]`).

## Install

```bash
pip install makethlm
```

Requires Python 3.10+. By default it uses the Claude CLI as backend, but any provider (OpenAI, Ollama, etc.) works via `--shell` or the `llm` directive.

Source and docs: [github.com/latedeployment/makethlm](https://github.com/latedeployment/makethlm)
