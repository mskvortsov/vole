#!/bin/sh -ex

nft delete table ip  vole_wan_snat
nft delete table ip6 vole_lan_masq
jool instance remove "vole-nat64"
