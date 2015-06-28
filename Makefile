.PHONY: \
	all \
	compile \
	clean \
	deps \
	dialyze \
	test

all: travis_ci dialyze

travis_ci: clean deps compile test

deps: deps_get deps_update

deps_get:
	@rebar get-deps

deps_update:
	@rebar update-deps

compile:
	@rebar compile

clean:
	@rebar clean

dialyze:
	@dialyzer deps/*/ebin/*.beam ebin/*.beam test/*.beam

test:
	@rebar ct skip_deps=true
