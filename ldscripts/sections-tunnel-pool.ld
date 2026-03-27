_tunnel_pool_start = ALIGN(4);

.dtls_pool (NOLOAD) : {
    KEEP(*libapp.a:dtls.c.obj(.noinit.*))
}

/* Overlap with the DTLS pool. */
.wireguard_pool _tunnel_pool_start (NOLOAD) : {
    KEEP(*wireguard.a:wg.c.obj(.noinit.*))
}

. = _tunnel_pool_start + MAX(SIZEOF(.dtls_pool), SIZEOF(.wireguard_pool));
