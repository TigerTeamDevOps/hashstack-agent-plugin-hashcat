all:

install:
	mkdir -p $(DESTDIR)/opt/hashstack/programs/
	mkdir -p $(DESTDIR)/opt/hashstack/agent/plugins/
	cp oclHashcat.json $(DESTDIR)/opt/hashstack/agent/plugins/
	7z x -o$(DESTDIR)/opt/hashstack/programs/ oclHashcat-2.01.7z
	mv $(DESTDIR)/opt/hashstack/programs/oclHashcat-2.01 $(DESTDIR)/opt/hashstack/programs/oclHashcat
	cd $(DESTDIR)/opt/hashstack/programs/oclHashcat && \
		rm -rfv charsets/ docs/ extra/ masks/ rules/ example* *.exe *.cmd *.sh *32.bin && \
		rm -fv kernels/4098/*VLIW4* kernels/4098/*VLIW5*

