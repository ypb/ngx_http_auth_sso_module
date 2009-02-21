
NAME=ngx_http_auth_sso_module
VERSION=0.0.1
PKG=$(NAME)-$(VERSION)

archive:
	rm -f ../$(PKG).tar.gz ../$(PKG).zip
	git archive --format=zip --prefix=$(PKG)/ > ../$(PKG).zip
	git archive --format=tar --prefix=$(PKG)/ | gzip ../$(PKG).tar.gz

clean:
	rm -f *~
