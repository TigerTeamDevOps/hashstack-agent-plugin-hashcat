all:

install:
	mkdir -p $(DESTDIR)/opt/hashstack/programs/
	mkdir -p $(DESTDIR)/opt/hashstack/agent/plugins/
	cp oclHashcat.json $(DESTDIR)/opt/hashstack/agent/plugins/
	7z x -o$(DESTDIR)/opt/hashstack/programs/ oclHashcat-1.32.7z
	mv $(DESTDIR)/opt/hashstack/programs/oclHashcat-1.32 $(DESTDIR)/opt/hashstack/programs/oclHashcat
	cd $(DESTDIR)/opt/hashstack/programs/oclHashcat && printf "\x84\x00\x00\x00" >eula.accepted && rm -rf charsets/ docs/ extra/ masks/ rules/ example* *.exe *.cmd *.sh *32.bin
