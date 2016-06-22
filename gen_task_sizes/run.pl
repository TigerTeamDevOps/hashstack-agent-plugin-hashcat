#!/usr/bin/env perl

use strict;
use warnings;
no strict 'subs'; 

sub usage
{
    print "usage: $0 <path to hashcat>\n";
}

my $hashcat = $ARGV[0] or die usage();
my $wordlist = 'bench.wl';
my $rules = 'bench.rule';

my @modes = (
    { mode => 0,     algorithm => 'MD5', hash => '8743b52063cd84097a65d1633f5c74f5' },
    { mode => 10,    algorithm => 'md5($pass.$salt)', hash => '01dfae6e5d4d90d9892622325959afbe:7050461' },
    { mode => 11,    algorithm => 'Joomla < 2.5.18', hash => '19e0e8d91c722e7091ca7a6a6fb0f4fa:54718031842521651757785603028777' },
    { mode => 12,    algorithm => 'PostgreSQL', hash => 'a6343a68d964ca596d9752250d54bb8a:postgres' },
    { mode => 20,    algorithm => 'md5($salt.$pass)', hash => 'f0fda58630310a6dd91a7d8f0a4ceda2:4225637426' },
    { mode => 21,    algorithm => 'osCommerce, xt:Commerce', hash => '374996a5e8a5e57fd97d893f7df79824:36' },
    { mode => 22,    algorithm => 'Juniper Netscreen/SSG (ScreenOS)', hash => 'nNxKL2rOEkbBc9BFLsVGG6OtOUO/8n:user' },
    { mode => 23,    algorithm => 'Skype', hash => '3af0389f093b181ae26452015f4ae728:user' },
    { mode => 30,    algorithm => 'md5(unicode($pass).$salt)', hash => 'b31d032cfdcf47a399990a71e43c5d2a:144816' },
    { mode => 40,    algorithm => 'md5($salt.unicode($pass))', hash => 'd63d0e21fdc05f618d55ef306c54af82:13288442151473' },
    { mode => 50,    algorithm => 'HMAC-MD5 (key = $pass)', hash => 'fc741db0a2968c39d9c2a5cc75b05370:1234' },
    { mode => 60,    algorithm => 'HMAC-MD5 (key = $salt)', hash => 'bfd280436f45fa38eaacac3b00518f29:1234' },
    { mode => 100,   algorithm => 'SHA1', hash => 'b89eaac7e61417341b710b727768294d0e6a277b' },
    { mode => 101,   algorithm => 'nsldap, SHA-1(Base64), Netscape LDAP SHA', hash => '{SHA}uJ6qx+YUFzQbcQtyd2gpTQ5qJ3s=' },
    { mode => 110,   algorithm => 'sha1($pass.$salt)', hash => '2fc5a684737ce1bf7b3b239df432416e0dd07357:2014' },
    { mode => 111,   algorithm => 'nsldaps, SSHA-1(Base64), Netscape LDAP SSHA', hash => '{SSHA}AZKja92fbuuB9SpRlHqaoXxbTc43Mzc2MDM1Ng==' },
    { mode => 112,   algorithm => 'Oracle 11g/12c', hash => 'ac5f1e62d21fd0529428b84d42e8955b04966703:38445748184477378130' },
    { mode => 120,   algorithm => 'sha1($salt.$pass)', hash => 'cac35ec206d868b7d7cb0b55f31d9425b075082b:5363620024' },
    { mode => 121,   algorithm => 'SMF > v1.1', hash => 'ecf076ce9d6ed3624a9332112b1cd67b236fdd11:17782686' },
    { mode => 122,   algorithm => 'OSX v10.4, v10.5, v10.6', hash => '1430823483d07626ef8be3fda2ff056d0dfd818dbfe47683' },
    { mode => 124,   algorithm => 'Django (SHA-1)', hash => 'sha1$fe76b$02d5916550edf7fc8c886f044887f4b1abf9b013' },
    { mode => 125,   algorithm => 'ArubaOS', hash => '5387280701327dc2162bdeb451d5a465af6d13eff9276efeba' },
    { mode => 130,   algorithm => 'sha1(unicode($pass).$salt)', hash => 'c57f6ac1b71f45a07dbd91a59fa47c23abcd87c2:631225' },
    { mode => 131,   algorithm => 'MSSQL(2000)', hash => '0x01002702560500000000000000000000000000000000000000008db43dd9b1972a636ad0c7d4b8c515cb8ce46578' },
    { mode => 132,   algorithm => 'MSSQL(2005)', hash => '0x010018102152f8f28c8499d8ef263c53f8be369d799f931b2fbe' },
    { mode => 133,   algorithm => 'PeopleSoft', hash => 'uXmFVrdBvv293L9kDR3VnRmx4ZM=' },
    { mode => 140,   algorithm => 'sha1($salt.unicode($pass))', hash => '5db61e4cd8776c7969cfd62456da639a4c87683a:8763434884872' },
    { mode => 141,   algorithm => 'EPiServer 6.x < v4', hash => '$episerver$*0*bEtiVGhPNlZpcUN4a3ExTg==*utkfN0EOgljbv5FoZ6+AcZD5iLk' },
    { mode => 150,   algorithm => 'HMAC-SHA1 (key = $pass)', hash => 'c898896f3f70f61bc3fb19bef222aa860e5ea717:1234' },
    { mode => 160,   algorithm => 'HMAC-SHA1 (key = $salt)', hash => 'd89c92b4400b15c39e462a8caa939ab40c3aeeea:1234' },
    { mode => 190,   algorithm => 'sha1(LinkedIn)', hash => 'b89eaac7e61417341b710b727768294d0e6a277b' },
    { mode => 200,   algorithm => 'MySQL323', hash => '7196759210defdc0' },
    { mode => 300,   algorithm => 'MySQL4.1/MySQL5', hash => 'FCF7C1B8749CF99D88E5F34271D636178FB5D130' },
    { mode => 400,   algorithm => 'phpass, MD5(Wordpress), MD5(phpBB3), MD5(Joomla)', hash => '$P$984478476IagS59wHZvyQMArzfx58u.' },
    { mode => 500,   algorithm => 'md5crypt, MD5(Unix), FreeBSD MD5, Cisco-IOS MD5', hash => '$1$28772684$iEwNOgGugqO9.bIz5sk8k/' },
    { mode => 501,   algorithm => 'Juniper IVE', hash => '3u+UR6n8AgABAAAAHxxdXKmiOmUoqKnZlf8lTOhlPYy93EAkbPfs5+49YLFd/B1+omSKbW7DoqNM40/EeVnwJ8kYoXv9zy9D5C5m5A==' },
    { mode => 900,   algorithm => 'MD4', hash => 'afe04867ec7a3845145579a95f72eca7' },
    { mode => 1000,  algorithm => 'NTLM', hash => 'b4b9b02e6f09a9bd760f388b67351e2b' },
    { mode => 1100,  algorithm => 'Domain Cached Credentials, mscash', hash => '4dd8965d1d476fa0d026722989a6b772:3060147285011' },
    { mode => 1400,  algorithm => 'SHA256', hash => '127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935' },
    { mode => 1410,  algorithm => 'sha256($pass.$salt)', hash => 'c73d08de890479518ed60cf670d17faa26a4a71f995c1dcc978165399401a6c4:53743528' },
    { mode => 1420,  algorithm => 'sha256($salt.$pass)', hash => 'eb368a2dfd38b405f014118c7d9747fcc97f4f0ee75c05963cd9da6ee65ef498:560407001617' },
    { mode => 1421,  algorithm => 'hMailServer', hash => '8fe7ca27a17adc337cd892b1d959b4e487b8f0ef09e32214f44fb1b07e461c532e9ec3' },
    { mode => 1430,  algorithm => 'sha256(unicode($pass).$salt)', hash => '4cc8eb60476c33edac52b5a7548c2c50ef0f9e31ce656c6f4b213f901bc87421:890128' },
    { mode => 1440,  algorithm => 'sha256($salt.unicode($pass))', hash => 'a4bd99e1e0aba51814e81388badb23ecc560312c4324b2018ea76393ea1caca9:12345678' },
    { mode => 1441,  algorithm => 'EPiServer 6.x > v4', hash => '$episerver$*1*MDEyMzQ1Njc4OWFiY2RlZg==*lRjiU46qHA7S6ZE7RfKUcYhB85ofArj1j7TrCtu3u6Y' },
    { mode => 1450,  algorithm => 'HMAC-SHA256 (key = $pass)', hash => 'abaf88d66bf2334a4a8b207cc61a96fb46c3e38e882e6f6f886742f688b8588c:1234' },
    { mode => 1460,  algorithm => 'HMAC-SHA256 (key = $salt)', hash => '8efbef4cec28f228fa948daaf4893ac3638fbae81358ff9020be1d7a9a509fc6:1234' },
    { mode => 1500,  algorithm => 'descrypt, DES(Unix), Traditional DES', hash => '48c/R8JAv757A' },
    { mode => 1600,  algorithm => 'md5apr1, MD5(APR), Apache MD5', hash => '$apr1$71850310$gh9m4xcAn3MGxogwX/ztb.' },
    { mode => 1700,  algorithm => 'SHA512', hash => '82a9dda829eb7f8ffe9fbe49e45d47d2dad9664fbb7adf72492e3c81ebd3e29134d9bc12212bf83c6840f10e8246b9db54a4859b7ccd0123d86e5872c1e5082f' },
    { mode => 1710,  algorithm => 'sha512($pass.$salt)', hash => 'e5c3ede3e49fb86592fb03f471c35ba13e8d89b8ab65142c9a8fdafb635fa2223c24e5558fd9313e8995019dcbec1fb584146b7bb12685c7765fc8c0d51379fd:6352283260' },
    { mode => 1711,  algorithm => 'SSHA-512(Base64), LDAP {SSHA512}', hash => '{SSHA512}ALtwKGBdRgD+U0fPAy31C28RyKYx7+a8kmfksccsOeLknLHv2DBXYI7TDnTolQMBuPkWDISgZr2cHfnNPFjGZTEyNDU4OTkw' },
    { mode => 1720,  algorithm => 'sha512($salt.$pass)', hash => '976b451818634a1e2acba682da3fd6efa72adf8a7a08d7939550c244b237c72c7d42367544e826c0c83fe5c02f97c0373b6b1386cc794bf0d21d2df01bb9c08a:2613516180127' },
    { mode => 1722,  algorithm => 'OSX v10.7', hash => '648742485c9b0acd786a233b2330197223118111b481abfa0ab8b3e8ede5f014fc7c523991c007db6882680b09962d16fd9c45568260531bdb34804a5e31c22b4cfeb32d' },
    { mode => 1730,  algorithm => 'sha512(unicode($pass).$salt)', hash => '13070359002b6fbb3d28e50fba55efcf3d7cc115fe6e3f6c98bf0e3210f1c6923427a1e1a3b214c1de92c467683f6466727ba3a51684022be5cc2ffcb78457d2:341351589' },
    { mode => 1731,  algorithm => 'MSSQL(2012), MSSQL(2014)', hash => '0x02000102030434ea1b17802fd95ea6316bd61d2c94622ca3812793e8fb1672487b5c904a45a31b2ab4a78890d563d2fcf5663e46fe797d71550494be50cf4915d3f4d55ec375' },
    { mode => 1740,  algorithm => 'sha512($salt.unicode($pass))', hash => 'bae3a3358b3459c761a3ed40d34022f0609a02d90a0d7274610b16147e58ece00cd849a0bd5cf6a92ee5eb5687075b4e754324dfa70deca6993a85b2ca865bc8:1237015423' },
    { mode => 1750,  algorithm => 'HMAC-SHA512 (key = $pass)', hash => '94cb9e31137913665dbea7b058e10be5f050cc356062a2c9679ed0ad6119648e7be620e9d4e1199220cd02b9efb2b1c78234fa1000c728f82bf9f14ed82c1976:1234' },
    { mode => 1760,  algorithm => 'HMAC-SHA512 (key = $salt)', hash => '7cce966f5503e292a51381f238d071971ad5442488f340f98e379b3aeae2f33778e3e732fcc2f7bdc04f3d460eebf6f8cb77da32df25500c09160dd3bf7d2a6b:1234' },
    { mode => 1800,  algorithm => 'sha512crypt, SHA512(Unix)', hash => '$6$52450745$k5ka2p8bFuSmoVT1tzOyyuaREkkKBcCNqoDKzYiJL9RaE8yMnPgh2XzzF0NDrUhgrcLwg78xs1w5pJiypEdFX/' },
    { mode => 2100,  algorithm => 'Domain Cached Credentials2, mscash2', hash => '$DCC2$10240#tom#e4e938d12fe5974dc42a90120bd9c90f' },
    { mode => 2400,  algorithm => 'Cisco-PIX MD5', hash => 'dRRVnUmUHXOTt9nk' },
    { mode => 2410,  algorithm => 'Cisco-ASA MD5', hash => '02dMBMYkTdC5Ziyp:36' },
    { mode => 2500,  algorithm => 'WPA/WPA2', hash => 'hashcat.hccap' },
    { mode => 2600,  algorithm => 'Double MD5', hash => 'a936af92b0ae20b1ff6c3347a72e5fbe' },
    { mode => 2611,  algorithm => 'vBulletin < v3.8.5', hash => '16780ba78d2d5f02f3202901c1b6d975:568' },
    { mode => 2612,  algorithm => 'PHPS', hash => '$PHPS$34323438373734$5b07e065b9d78d69603e71201c6cf29f' },
    { mode => 2711,  algorithm => 'vBulletin > v3.8.5', hash => 'bf366348c53ddcfbd16e63edfdd1eee6:181264250056774603641874043270' },
    { mode => 2811,  algorithm => 'IPB2+, MyBB1.2+', hash => '8d2129083ef35f4b365d5d87487e1207:47204' },
    { mode => 3000,  algorithm => 'LM', hash => '299bd128c1101fd6' },
    { mode => 3100,  algorithm => 'Oracle 7-10g, DES(Oracle)', hash => '7A963A529D2E3229:3682427524' },
    { mode => 3200,  algorithm => 'bcrypt', hash => '$2a$05$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6' },
    { mode => 3710,  algorithm => 'md5($salt.md5($pass))', hash => '95248989ec91f6d0439dbde2bd0140be:1234' },
    { mode => 3711,  algorithm => 'Mediawiki B type', hash => '$B$56668501$0ce106caa70af57fd525aeaf80ef2898' },
    { mode => 3800,  algorithm => 'md5($pass.$salt.$pass)', hash => '2e45c4b99396c6cb2db8bda0d3df669f:1234' },
    { mode => 4300,  algorithm => 'md5(strtoupper(md5($pass)))', hash => 'b8c385461bb9f9d733d3af832cf60b27' },
    { mode => 4400,  algorithm => 'md5(sha1($pass))', hash => '288496df99b33f8f75a7ce4837d1b480' },
    { mode => 4500,  algorithm => 'Double SHA1', hash => '3db9184f5da4e463832b086211af8d2314919951' },
    { mode => 4700,  algorithm => 'sha1(md5($pass))', hash => '92d85978d884eb1d99a51652b1139c8279fa8663' },
    { mode => 4800,  algorithm => 'MD5(Chap), iSCSI CHAP authentication', hash => 'afd09efdd6f8ca9f18ec77c5869788c3:01020304050607080910111213141516:01' },
    { mode => 4900,  algorithm => 'sha1($salt.$pass.$salt)', hash => '85087a691a55cbb41ae335d459a9121d54080b80:488387841' },
    { mode => 5000,  algorithm => 'SHA-3(Keccak)', hash => '203f88777f18bb4ee1226627b547808f38d90d3e106262b5de9ca943b57137b6' },
    { mode => 5100,  algorithm => 'Half MD5', hash => '8743b52063cd8409' },
    { mode => 5200,  algorithm => 'Password Safe v3', hash => 'hashcat.psafe3' },
    { mode => 5300,  algorithm => 'IKE-PSK MD5', hash => 'hashcat.ikemd5' },
    { mode => 5400,  algorithm => 'IKE-PSK SHA1', hash => 'hashcat.ikesha1' },
    { mode => 5500,  algorithm => 'NetNTLMv1-VANILLA / NetNTLMv1+ESS', hash => 'u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41:cb8086049ec4736c' },
    { mode => 5600,  algorithm => 'NetNTLMv2', hash => 'admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e0000000052920b85f78d013c31cdb3b92f5d765c783030' },
    { mode => 5700,  algorithm => 'Cisco-IOS SHA256', hash => '2btjjy78REtmYkkW0csHUbJZOstRXoWdX1mGrmmfeHI' },
    { mode => 5800,  algorithm => 'Samsung Android Password/PIN', hash => '0223b799d526b596fe4ba5628b9e65068227e68e:f6d45822728ddb2c' },
    { mode => 6000,  algorithm => 'RipeMD160', hash => '012cb9b334ec1aeb71a9c8ce85586082467f7eb6' },
    { mode => 6100,  algorithm => 'Whirlpool', hash => '7ca8eaaaa15eaa4c038b4c47b9313e92da827c06940e69947f85bc0fbef3eb8fd254da220ad9e208b6b28f6bb9be31dd760f1fdb26112d83f87d96b416a4d258' },
    { mode => 6211,  algorithm => 'TrueCrypt 5.0+ RipeMD160 (No Cascading)', hash => 'hashcat_ripemd160_aes.tc' },
    { mode => 6212,  algorithm => 'TrueCrypt 5.0+ RipeMD160 (2-cipher Cascade)', hash => 'hashcat_ripemd160_aes-twofish.tc' },
    { mode => 6213,  algorithm => 'TrueCrypt 5.0+ RipeMD160 (3-cipher Cascade)', hash => 'hashcat_ripemd160_aes-twofish-serpent.tc' },
    { mode => 6221,  algorithm => 'TrueCrypt 5.0+ SHA512 (No Cascading)', hash => 'hashcat_sha512_aes.tc' },
    { mode => 6222,  algorithm => 'TrueCrypt 5.0+ SHA512 (2-cipher Cascade)', hash => 'hashcat_sha512_aes-twofish.tc' },
    { mode => 6223,  algorithm => 'TrueCrypt 5.0+ SHA512 (3-cipher Cascade)', hash => 'hashcat_sha512_aes-twofish-serpent.tc' },
    { mode => 6231,  algorithm => 'TrueCrypt 5.0+ Whirlpool (No Cascading)', hash => 'hashcat_whirlpool_aes.tc' },
    { mode => 6232,  algorithm => 'TrueCrypt 5.0+ Whirlpool (2-cipher Cascade)', hash => 'hashcat_whirlpool_aes-twofish.tc' },
    { mode => 6233,  algorithm => 'TrueCrypt 5.0+ Whirlpool (3-cipher Cascade)', hash => 'hashcat_whirlpool_aes-twofish-serpent.tc' },
    { mode => 6241,  algorithm => 'TrueCrypt 5.0+ RipeMD160 boot mode (No Cascading)', hash => 'hashcat_ripemd160_aes_boot.tc' },
    { mode => 6242,  algorithm => 'TrueCrypt 5.0+ RipeMD160 boot mode (2-cipher Cascade)', hash => 'hashcat_ripemd160_aes-twofish_boot.tc' },
    { mode => 6243,  algorithm => 'TrueCrypt 5.0+ RipeMD160 boot mode (3-cipher Cascade)', hash => 'hashcat_ripemd160_serpent-twofish-aes_boot.tc' },
    { mode => 6300,  algorithm => 'AIX {smd5}', hash => '{smd5}a5/yTL/u$VfvgyHx1xUlXZYBocQpQY0' },
    { mode => 6400,  algorithm => 'AIX {ssha256}', hash => '{ssha256}06$aJckFGJAB30LTe10$ohUsB7LBPlgclE3hJg9x042DLJvQyxVCX.nZZLEz.g2' },
    { mode => 6500,  algorithm => 'AIX {ssha512}', hash => '{ssha512}06$bJbkFGJAB30L2e23$bXiXjyH5YGIyoWWmEVwq67nCU5t7GLy9HkCzrodRCQCx3r9VvG98o7O3V0r9cVrX3LPPGuHqT5LLn0oGCuI1..' },
    { mode => 6600,  algorithm => '1Password, agilekeychain', hash => 'hashcat.agilekeychain' },
    { mode => 6700,  algorithm => 'AIX {ssha1}', hash => '{ssha1}06$bJbkFGJAB30L2e23$dCESGOsP7jaIIAJ1QAcmaGeG.kr' },
    { mode => 6800,  algorithm => 'Lastpass', hash => 'a2d1f7b7a1862d0d4a52644e72d59df5:500:lp@trash-mail.com' },
    { mode => 6900,  algorithm => 'GOST R 34.11-94', hash => 'df226c2c6dcb1d995c0299a33a084b201544293c31fc3d279530121d36bbcea9' },
    { mode => 7100,  algorithm => 'OSX v10.8 / v10.9', hash => '$ml$35460$93a94bd24b5de64d79a5e49fa372827e739f4d7b6975c752c9a0ff1e5cf72e05$752351df64dd2ce9dc9c64a72ad91de6581a15c19176266b44d98919dfa81f0f96cbcb20a1ffb400718c20382030f637892f776627d34e021bad4f81b7de8222' },
    { mode => 7200,  algorithm => 'GRUB 2', hash => 'grub.pbkdf2.sha512.10000.7d391ef48645f626b427b1fae06a7219b5b54f4f02b2621f86b5e36e83ae492bd1db60871e45bc07925cecb46ff8ba3db31c723c0c6acbd4f06f60c5b246ecbf.26d59c52b50df90d043f070bd9cbcd92a74424da42b3666fdeb08f1a54b8f1d2f4f56cf436f9382419c26798dc2c209a86003982b1e5a9fcef905f4dfaa4c524' },
    { mode => 7300,  algorithm => 'IPMI2 RAKP HMAC-SHA1', hash => 'b7c2d6f13a43dce2e44ad120a9cd8a13d0ca23f0414275c0bbe1070d2d1299b1c04da0f1a0f1e4e2537300263a2200000000000000000000140768617368636174:472bdabe2d5d4bffd6add7b3ba79a291d104a9ef' },
    { mode => 7400,  algorithm => 'sha256crypt, SHA256(Unix)', hash => '$5$rounds=5000$GX7BopJZJxPc/KEK$le16UF8I2Anb.rOrn22AUPWvzUETDGefUmAV8AZkGcD' },
    { mode => 7500,  algorithm => 'Kerberos 5 AS-REQ Pre-Auth etype 23', hash => '$krb5pa$23$user$realm$salt$4e751db65422b2117f7eac7b721932dc8aa0d9966785ecd958f971f622bf5c42dc0c70b532363138363631363132333238383835' },
    { mode => 7600,  algorithm => 'Redmine Project Management Web App', hash => '1fb46a8f81d8838f46879aaa29168d08aa6bf22d:3290afd193d90e900e8021f81409d7a9' },
    { mode => 7700,  algorithm => 'SAP CODVN B (BCODE)', hash => 'user$c8b48f26b87b7ea7' },
    { mode => 7800,  algorithm => 'SAP CODVN F/G (PASSCODE)', hash => 'user$abcad719b17e7f794df7e686e563e9e2d24de1d0' },
    { mode => 7900,  algorithm => 'Drupal7', hash => '$S$C33783772bRXEx1aCsvY.dqgaaSu76XmVlKrW9Qu8IQlvxHlmzLf' },
    { mode => 8000,  algorithm => 'Sybase ASE', hash => '0xc00778168388631428230545ed2c976790af96768afa0806fe6c0da3b28f3e132137eac56f9bad027ea2' },
    { mode => 8100,  algorithm => 'Citrix Netscaler', hash => '1765058016a22f1b4e076dccd1c3df4e8e5c0839ccded98ea' },
    { mode => 8200,  algorithm => '1Password, cloudkeychain', hash => 'hashcat.cloudkeychain' },
    { mode => 8300,  algorithm => 'DNSSEC (NSEC3)', hash => '7b5n74kq8r441blc2c5qbbat19baj79r:.lvdsiqfj.net:33164473:1' },
    { mode => 8400,  algorithm => 'WBB3, Woltlab Burning Board 3', hash => '8084df19a6dc81e2597d051c3d8b400787e2d5a9:6755045315424852185115352765375338838643' },
    { mode => 8500,  algorithm => 'RACF', hash => '$racf$*USER*FC2577C6EBE6265B' },
    { mode => 8600,  algorithm => 'Lotus Notes/Domino 5', hash => '3dd2e1e5ac03e230243d58b8c5ada076' },
    { mode => 8700,  algorithm => 'Lotus Notes/Domino 6', hash => '(GDpOtD35gGlyDksQRxEU)' },
    { mode => 8800,  algorithm => 'Android FDE <= 4.3', hash => 'hashcat.android43fde' },
    { mode => 8900,  algorithm => 'scrypt', hash => 'SCRYPT:1024:1:1:MDIwMzMwNTQwNDQyNQ==:5FW+zWivLxgCWj7qLiQbeC8zaNQ+qdO0NUinvqyFcfo=' },
    { mode => 9000,  algorithm => 'Password Safe v2', hash => 'hashcat.psafe2.dat' },
    { mode => 9100,  algorithm => 'Lotus Notes/Domino 8', hash => '(HsjFebq0Kh9kH7aAZYc7kY30mC30mC3KmC30mCluagXrvWKj1)' },
    { mode => 9200,  algorithm => 'Cisco $8$', hash => '$8$TnGX/fE4KGHOVU$pEhnEvxrvaynpi8j4f.EMHr6M.FzU8xnZnBr/tJdFWk' },
    { mode => 9300,  algorithm => 'Cisco $9$', hash => '$9$2MJBozw/9R3UsU$2lFhcKvpghcyw8deP25GOfyZaagyUOGBymkryvOdfo6' },
    { mode => 9400,  algorithm => 'Microsoft Office 2007', hash => '$office$*2007*20*128*16*411a51284e0d0200b131a8949aaaa5cc*117d532441c63968bee7647d9b7df7d6*df1d601ccf905b375575108f42ef838fb88e1cde' },
    { mode => 9500,  algorithm => 'Microsoft Office 2010', hash => '$office$*2010*100000*128*16*77233201017277788267221014757262*b2d0ca4854ba19cf95a2647d5eee906c*e30cbbb189575cafb6f142a90c2622fa9e78d293c5b0c001517b3f5b82993557' },
    { mode => 9600,  algorithm => 'Microsoft Office 2013', hash => '$office$*2013*100000*256*16*7dd611d7eb4c899f74816d1dec817b3b*948dc0b2c2c6c32f14b5995a543ad037*0b7ee0e48e935f937192a59de48a7d561ef2691d5c8a3ba87ec2d04402a94895' },
    { mode => 9700,  algorithm => 'Microsoft Office 97-2003 MD5 + RC4', hash => '$oldoffice$1*04477077758555626246182730342136*b1b72ff351e41a7c68f6b45c4e938bd6*0d95331895e99f73ef8b6fbc4a78ac1a' },
    { mode => 9800,  algorithm => 'Microsoft Office 97-2003 SHA1 + RC4', hash => '$oldoffice$3*83328705222323020515404251156288*2855956a165ff6511bc7f4cd77b9e101*941861655e73a09c40f7b1e9dfd0c256ed285acd' },
    { mode => 9900,  algorithm => 'Radmin2', hash => '22527bee5c29ce95373c4e0f359f079b' },
    { mode => 10000, algorithm => 'Django (PBKDF2-SHA256)', hash => 'pbkdf2_sha256$20000$H0dPx8NeajVu$GiC4k5kqbbR9qWBlsRgDywNqC2vd9kqfk7zdorEnNas=' },
    { mode => 10100, algorithm => 'SipHash', hash => 'ad61d78c06037cd9:2:4:81533218127174468417660201434054' },
    { mode => 10200, algorithm => 'Cram MD5', hash => '$cram_md5$PG5vLXJlcGx5QGhhc2hjYXQubmV0Pg==$dXNlciA0NGVhZmQyMmZlNzY2NzBmNmIyODc5MDgxYTdmNWY3MQ==' },
    { mode => 10300, algorithm => 'SAP CODVN H (PWDSALTEDHASH)', hash => '{x-issha, 1024}C0624EvGSdAMCtuWnBBYBGA0chvqAflKY74oEpw/rpY=' },
    { mode => 10400, algorithm => 'Adobe PDF 1.1 - 1.3 (Acrobat 2 - 4)', hash => '$pdf$1*2*40*-1*0*16*51726437280452826511473255744374*32*9b09be05c226214fa1178342673d86f273602b95104f2384b6c9b709b2cbc058*32*0000000000000000000000000000000000000000000000000000000000000000' },
    { mode => 10500, algorithm => 'Adobe PDF 1.4 - 1.6 (Acrobat 5 - 8)', hash => '$pdf$2*3*128*-1028*1*16*da42ee15d4b3e08fe5b9ecea0e02ad0f*32*c9b59d72c7c670c42eeb4fca1d2ca15000000000000000000000000000000000*32*c4ff3e868dc87604626c2b8c259297a14d58c6309c70b00afdfb1fbba10ee571' },
    { mode => 10600, algorithm => 'Adobe PDF 1.7 Level 3 (Acrobat 9)', hash => '$pdf$5*5*256*-1028*1*16*20583814402184226866485332754315*127*f95d927a94829db8e2fbfbc9726ebe0a391b22a084ccc2882eb107a74f7884812058381440218422686648533275431500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000*127*00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000*32*0000000000000000000000000000000000000000000000000000000000000000*32*0000000000000000000000000000000000000000000000000000000000000000' },
    { mode => 10700, algorithm => 'Adobe PDF 1.7 Level 8 (Acrobat 10 - 11)', hash => '$pdf$5*6*256*-4*1*16*381692e488413f5502fa7314a78c25db*48*e5bf81a2a23c88f3dccb44bc7da68bb5606b653b733bcf9adaa5eb2c8ccf53abba66539044eb1957eda68469b1d0b9b5*48*b222df06deb308bf919d13447e688775fdcab972faed2c866dc023a126cb4cd4bbffab3683ecde243cf8d88967184680' },
    { mode => 10800, algorithm => 'SHA384', hash => '07371af1ca1fca7c6941d2399f3610f1e392c56c6d73fddffe38f18c430a2817028dae1ef09ac683b62148a2c8757f42' },
    { mode => 10900, algorithm => 'PBKDF2-HMAC-SHA256', hash => 'sha256:1000:MTc3MTA0MTQwMjQxNzY=:PYjCU215Mi57AYPKva9j7mvF4Rc5bCnt' },
    { mode => 11000, algorithm => 'PrestaShop', hash => '810e3d12f0f10777a679d9ca1ad7a8d9:M2uZ122bSHJ4Mi54tXGY0lqcv1r28mUluSkyw37ou5oia4i239ujqw0l' },
    { mode => 11100, algorithm => 'PostgreSQL Challenge-Response Authentication (MD5)', hash => '$postgres$postgres*f0784ea5*2091bb7d4725d1ca85e8de6ec349baf6' },
    { mode => 11200, algorithm => 'MySQL Challenge-Response Authentication (SHA1)', hash => '$mysqlna$1c24ab8d0ee94d70ab1f2e814d8f0948a14d10b9*437e93572f18ae44d9e779160c2505271f85821d' },
    { mode => 11300, algorithm => 'Bitcoin/Litecoin wallet.dat', hash => '$bitcoin$96$d011a1b6a8d675b7a36d0cd2efaca32a9f8dc1d57d6d01a58399ea04e703e8bbb44899039326f7a00f171a7bbc854a54$16$1563277210780230$158555$96$628835426818227243334570448571536352510740823233055715845322741625407685873076027233865346542174$66$625882875480513751851333441623702852811440775888122046360561760525' },
    { mode => 11400, algorithm => 'SIP digest authentication (MD5)', hash => '$sip$*192.168.100.100*192.168.100.121*username*asterisk*REGISTER*sip*192.168.100.121**2b01df0b****MD5*ad0520061ca07c120d7e8ce696a6df2d' },
    { mode => 11500, algorithm => 'CRC32', hash => 'c762de4a:00000000' },
    { mode => 11600, algorithm => '7zip', hash => '$7z$0$19$0$salt$8$f6196259a7326e3f0000000000000000$185065650$112$98$f3bc2a88062c419a25acd40c0c2d75421cf23263f69c51b13f9b1aada41a8a09f9adeae45d67c60b56aad338f20c0dcc5eb811c7a61128ee0746f922cdb9c59096869f341c7a9cb1ac7bb7d771f546b82cf4e6f11a5ecd4b61751e4d8de66dd6e2dfb5b7d1022d2211e2d66ea1703f96' },
    { mode => 11700, algorithm => 'GOST R 34.11-2012 (Streebog) 256-bit', hash => '57e9e50caec93d72e9498c211d6dc4f4d328248b48ecf46ba7abfa874f666e36' },
    { mode => 11800, algorithm => 'GOST R 34.11-2012 (Streebog) 512-bit', hash => '5d5bdba48c8f89ee6c0a0e11023540424283e84902de08013aeeb626e819950bb32842903593a1d2e8f71897ff7fe72e17ac9ba8ce1d1d2f7e9c4359ea63bdc3' },
    { mode => 11900, algorithm => 'PBKDF2-HMAC-MD5', hash => 'md5:1000:MTg1MzA=:Lz84VOcrXd699Edsj34PP98+f4f3S0rTZ4kHAIHoAjs=' },
    { mode => 12000, algorithm => 'PBKDF2-HMAC-SHA1', hash => 'sha1:1000:MzU4NTA4MzIzNzA1MDQ=:19ofiY+ahBXhvkDsp0j2ww==' },
    { mode => 12100, algorithm => 'PBKDF2-HMAC-SHA512', hash => 'sha512:1000:ODQyMDEwNjQyODY=:MKaHNWXUsuJB3IEwBHbm3w==' },
    { mode => 12200, algorithm => 'eCryptfs', hash => '$ecryptfs$0$1$7c95c46e82f364b3$60bba503f0a42d0c' },
    { mode => 12300, algorithm => 'Oracle T: Type (Oracle 12+)', hash => '78281A9C0CF626BD05EFC4F41B515B61D6C4D95A250CD4A605CA0EF97168D670EBCB5673B6F5A2FB9CC4E0C0101E659C0C4E3B9B3BEDA846CD15508E88685A2334141655046766111066420254008225' },
    { mode => 12400, algorithm => 'BSDiCrypt, Extended DES', hash => '_9G..8147mpcfKT8g0U.' },
    { mode => 12500, algorithm => 'RAR v3', hash => '$RAR3$*0*45109af8ab5f297a*adbf6c5385d7a40373e8f77d7b89d317' },
    { mode => 12600, algorithm => 'ColdFusion 10+', hash => 'aee9edab5653f509c4c63e559a5e967b4c112273bc6bd84525e630a3f9028dcb:5136256866783777334574783782810410706883233321141647265340462733' },
    { mode => 12700, algorithm => 'Blockchain.info Wallet', hash => '$blockchain$288$5420055827231730710301348670802335e45a6f5f631113cb1148a6e96ce645ac69881625a115fd35256636d0908217182f89bdd53256a764e3552d3bfe68624f4f89bb6de60687ff1ebb3cbf4e253ee3bea0fe9d12d6e8325ddc48cc924666dc017024101b7dfb96f1f45cfcf642c45c83228fe656b2f88897ced2984860bf322c6a89616f6ea5800aadc4b293ddd46940b3171a40e0cca86f66f0d4a487aa3a1beb82569740d3bc90bc1cb6b4a11bc6f0e058432cc193cb6f41e60959d03a84e90f38e54ba106fb7e2bfe58ce39e0397231f7c53a4ed4fd8d2e886de75d2475cc8fdc30bf07843ed6e3513e218e0bb75c04649f053a115267098251fd0079272ec023162505725cc681d8be12507c2d3e1c9520674c68428df1739944b8ac' },
    { mode => 12800, algorithm => 'MS-AzureSync PBKDF2-HMAC-SHA256', hash => 'v1;PPH1_MD4,84840328224366186645,100,005a491d8bf3715085d69f934eef7fb19a15ffc233b5382d9827910bc32f3506' },
    { mode => 12900, algorithm => 'Android FDE (Samsung DEK)', hash => '38421854118412625768408160477112384218541184126257684081604771129b6258eb22fc8b9d08e04e6450f72b98725d7d4fcad6fb6aec4ac2a79d0c6ff738421854118412625768408160477112' },
    { mode => 13000, algorithm => 'RAR v5', hash => '$rar5$16$74575567518807622265582327032280$15$f8b4064de34ac02ecabfe9abdf93ed6a$8$9843834ed0f7c754' },
    { mode => 13100, algorithm => 'Kerberos 5 TGS-REP etype 23', hash => '$krb5tgs$23$*user$realm$test/spn*$140964709dbdeccbc6121b675ccfb8b2$af937e9d5691b74600e514a3105976f1a8ddb2eed3aeb008ea74ff50bee7a65f14e8c1cbbc360687e6d867c9fbe2e4b2004d0584f0c283a18f613c69c756f78c001647e01da84466f59c655a25913b0cb4e42f0dc88f461e921441da40d6fb56d40545f71b841d00f019f135eb93c2357253796e5dc7da8a455d4fe17c966c3ea3ac620eb5e51c44c8a9cc48d385680c64c519e2113497315e7d7623044d48e2272bd9836b754755c3494040b487757a936780daeff859dd2c8839' },
    { mode => 13200, algorithm => 'AxCrypt', hash => '$axcrypt$*1*10000*aaf4a5b4a7185551fea2585ed69fe246*45c616e901e48c6cac7ff14e8cd99113393be259c595325e' },
    { mode => 13300, algorithm => 'AxCrypt in-memory SHA1', hash => '$axcrypt_sha1$b89eaac7e61417341b710b727768294d0e6a277b' },
    { mode => 13400, algorithm => 'KeePass', hash => '$keepass$*1*50000*0*375756b9e6c72891a8e5645a3338b8c8*82afc053e8e1a6cfa39adae4f5fe5e59f545a54d6956593d1709b39cacd7f796*c698fbfc7d1b71431d10611e2216ab21*24a63140f4eb3bfd7d59b7694eea38d1d93a43bc3af989755d2b326286c4d510*1*192*1a65072f436e9da0c9e832eca225a04ab78821b55d9f550860ade2ef8126a2c4050cf4d033374abd3dac6d0c5907c6cbb033643b203825c12e6c9853b5ac17a4809559fe723e01b4a2ab87cc83c8ba7ee4a757b8a0cf1674106f21f6675cba12064443d65436650df10ea0923c4cadfd4bfe341a6f4fa23a1a67f7d12a489fc5410ef6db9f6607905de491d3b3b915852a1b6c231c96366cbdee5ea9bd7f73ffd2f7a579215528ae1bf0ea540947ebfe39ca84bc6cbeded4f8e8fb6ed8f32dd5' },
    { mode => 13500, algorithm => 'PeopleSoft PS_TOKEN', hash => 'b5e335754127b25ba6f99a94c738e24cd634c35a:aa07d396f5038a6cbeded88d78d1d6c907e4079b3dc2e12fddee409a51cc05ae73e8cc24d518c923a2f79e49376594503e6238b806bfe33fa8516f4903a9b4' },
    { mode => 13600, algorithm => 'WinZIP AES', hash => '$zip2$*0*3*0*b5d2b7bf57ad5e86a55c400509c672bd*d218*0**ca3d736d03a34165cfa9*$/zip2$' },
    { mode => 13711, algorithm => 'VeraCrypt RipeMD160 XTS 512-bit', hash => 'hashcat_ripemd160_aes.tc' },
    { mode => 13712, algorithm => 'VeraCrypt RipeMD160 XTS 1024-bit', hash => 'hashcat_ripemd160_aes.tc' },
    { mode => 13713, algorithm => 'VeraCrypt RipeMD160 XTS 1536-bit', hash => 'hashcat_ripemd160_aes.tc' },
    { mode => 13721, algorithm => 'VeraCrypt SHA512 XTS 512-bit', hash => 'hashcat_ripemd160_aes.tc' },
    { mode => 13722, algorithm => 'VeraCrypt SHA512 XTS 1024-bit', hash => 'hashcat_ripemd160_aes.tc' },
    { mode => 13723, algorithm => 'VeraCrypt SHA512 XTS 1536-bit', hash => 'hashcat_ripemd160_aes.tc' },
    { mode => 13731, algorithm => 'VeraCrypt Whirlpool XTS 512-bit', hash => 'hashcat_ripemd160_aes.tc' },
    { mode => 13732, algorithm => 'VeraCrypt Whirlpool XTS 1024-bit', hash => 'hashcat_ripemd160_aes.tc' },
    { mode => 13733, algorithm => 'VeraCrypt Whirlpool XTS 1536-bit', hash => 'hashcat_ripemd160_aes.tc' },
    { mode => 13741, algorithm => 'VeraCrypt RipeMD160 boot mode XTS 512-bit', hash => 'hashcat_ripemd160_aes.tc' },
    { mode => 13742, algorithm => 'VeraCrypt RipeMD160 boot mode XTS 1024-bit', hash => 'hashcat_ripemd160_aes.tc' },
    { mode => 13743, algorithm => 'VeraCrypt RipeMD160 boot mode XTS 1536-bit', hash => 'hashcat_ripemd160_aes.tc' },
    { mode => 13751, algorithm => 'VeraCrypt SHA256 XTS 512-bit', hash => 'hashcat_ripemd160_aes.tc' },
    { mode => 13752, algorithm => 'VeraCrypt SHA256 XTS 1024-bit', hash => 'hashcat_ripemd160_aes.tc' },
    { mode => 13753, algorithm => 'VeraCrypt SHA256 XTS 1536-bit', hash => 'hashcat_ripemd160_aes.tc' },
    { mode => 13761, algorithm => 'VeraCrypt SHA256 boot mode XTS 512-bit', hash => 'hashcat_ripemd160_aes.tc' },
    { mode => 13762, algorithm => 'VeraCrypt SHA256 boot mode XTS 1024-bit', hash => 'hashcat_ripemd160_aes.tc' },
    { mode => 13763, algorithm => 'VeraCrypt SHA256 boot mode XTS 1536-bit', hash => 'hashcat_ripemd160_aes.tc' },
    { mode => 13800, algorithm => 'Windows 8+ Phone PIN/Password', hash => '95fc4680bcd2a5f25de3c580cbebadbbf256c1f0ff2e9329c58e36f8b914c11f:4471347156480581513210137061422464818088437334031753080747625028271635402815635172140161077854162657165115624364524648202480341513407048222056541500234214433548175101668212658151115765112202168288664210443352443335235337677853484573107775345675846323265745' }
);

open (my $cpu, '>', '../hashcat-cpu.json') or die "could not open cpu config file\n";
open (my $gpu, '>', '../hashcat-gpu.json') or die "could not open gpu config file\n";

print $cpu "{\n";
print $cpu "    \"algorithms\": [\n";

print $gpu "{\n";
print $gpu "    \"algorithms\": [\n";


foreach my $entry (@modes)
{
    my $tasksize = 0;
    my $algorithm = $entry->{'algorithm'};
    my $mode = $entry->{'mode'};
    my $hash = $entry->{'hash'};

    $tasksize = `$hashcat --opencl-platform 2 --opencl-device-types 1 -d 1 -w 3 --weak-hash-threshold 0 --restore-disable --logfile-disable --potfile-disable --gpu-temp-disable --status --machine-readable --runtime 20 --status-timer 20 -m $mode '$hash' $wordlist -r $rules | sed -rn 's/STATUS.*PROGRESS\\t([0-9]+)\\t.*/\\1/p' | tail -n 1`;

    if ($tasksize != 0)
    {
        $tasksize *= 10;    # progress made in 20 sec * 10 ~= progress made in 200 sec
    }
    else
    {
        $tasksize = `$hashcat --opencl-platform 2 --opencl-device-types 1 -d 1 -w 3 --weak-hash-threshold 0 --restore-disable --logfile-disable --potfile-disable --gpu-temp-disable --status --machine-readable --runtime 100 --status-timer 100 -m $mode '$hash' $wordlist -r $rules | sed -rn 's/STATUS.*PROGRESS\\t([0-9]+)\\t.*/\\1/p' | tail -n 1`;

        $tasksize *= 2;     # progress made in 100 sec * 2 ~= progress made in 200 sec
    }

    print $cpu "        {\n";
    print $cpu "            \"algorithm\": \"$algorithm\",\n";
    print $cpu "            \"device\": \"cpu\",\n";
    print $cpu "            \"keyspace_hack\": true,\n";
    print $cpu "            \"mode\": \"$mode\",\n";
    print $cpu "            \"tasksize\": $tasksize\n";

    if ($mode == $modes[-1]{'mode'})
    {
        print $cpu "        }\n";
    }
    else
    {
        print $cpu "        },\n";
    }

    $tasksize = 0;

    $tasksize = `$hashcat --opencl-platform 1 --opencl-device-types 2 -d 1 -w 3 --weak-hash-threshold 0 --restore-disable --logfile-disable --potfile-disable --gpu-temp-disable --status --machine-readable --runtime 20 --status-timer 20 -m $mode '$hash' $wordlist -r $rules | sed -rn 's/STATUS.*PROGRESS\\t([0-9]+)\\t.*/\\1/p' | tail -n 1`;

    if ($tasksize != 0)
    {
        $tasksize *= 10;
    }
    else
    {
        $tasksize = `$hashcat --opencl-platform 1 --opencl-device-types 2 -d 1 -w 3 --weak-hash-threshold 0 --restore-disable --logfile-disable --potfile-disable --gpu-temp-disable --status --machine-readable --runtime 100 --status-timer 100 -m $mode '$hash' $wordlist -r $rules | sed -rn 's/STATUS.*PROGRESS\\t([0-9]+)\\t.*/\\1/p' | tail -n 1`;

         $tasksize *= 2;
    }

    print $gpu "        {\n";
    print $gpu "            \"algorithm\": \"$algorithm\",\n";
    print $gpu "            \"device\": \"gpu\",\n";
    print $gpu "            \"keyspace_hack\": true,\n";
    print $gpu "            \"mode\": \"$mode\",\n";
    print $gpu "            \"tasksize\": $tasksize\n";

    if ($mode == $modes[-1]{'mode'})
    {
        print $gpu "        }\n";
    }
    else
    {
        print $gpu "        },\n";
    }
}
