all:
	$(MAKE) -C libev
	$(MAKE) -C Option-Parse
	$(MAKE) -C exs-util
	$(MAKE) -C packet-shuffler

clean:
	cd libev ; rm -rf libev-4.15 ; tar -xvzf ./libev-4.15.tar.gz
	$(MAKE) -C Option-Parse clean
	$(MAKE) -C exs-util clean
	$(MAKE) -C packet-shuffler clean

.PHONY: clean
