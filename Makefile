REBAR := ./rebar3

.PHONY: \
	all \
	compile \
	clean \
	deps \
	dialyze \
	test

all:
	$(MAKE) compile
	$(MAKE) dialyze
	$(MAKE) test

travis_ci:
	rebar3 compile
	rebar3 do dialyzer
	rebar3 as test do eunit,cover

deps:
	@$(REBAR) get-deps

compile:
	@$(REBAR) compile

clean:
	@$(REBAR) clean

dialyze:
	@$(REBAR) do dialyzer

test:
	@$(REBAR) as test do eunit,cover
