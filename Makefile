VERSION = 3.00-beta-93

all:

install:
	mkdir -p $(DESTDIR)/opt/hashstack/programs/
	mkdir -p $(DESTDIR)/opt/hashstack/agent/plugins/
	cp hashcat-cpu.json $(DESTDIR)/opt/hashstack/agent/plugins/
	cp hashcat-gpu.json $(DESTDIR)/opt/hashstack/agent/plugins/
	7z x -o$(DESTDIR)/opt/hashstack/programs/ hashcat-$(VERSION).7z
	mv $(DESTDIR)/opt/hashstack/programs/hashcat-3.00 $(DESTDIR)/opt/hashstack/programs/hashcat
	cd $(DESTDIR)/opt/hashstack/programs/hashcat && \
		rm -rfv charsets/ docs/ extra/ masks/ rules/ kernels/* example* *.exe *.cmd *.sh *32.bin


