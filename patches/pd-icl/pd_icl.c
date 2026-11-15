/* SPDX-License-Identifier: GPL-2.0-only */
/* Pinned OS3.0.306.0 degas ABI; see patch-module.py. No PD writes. */
typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long u64;

extern int usb_get_property(unsigned int property, int *value);
extern int adapter_dev_get_cap(void *adapter, int type, void *cap);
extern int adapter_dev_get_property(void *adapter, int property);
extern int tcpm_inquire_pd_contract(void *tcpc, int *mv, int *ma);
extern void mutex_lock(void *mutex);
extern void mutex_unlock(void *mutex);
extern int get_vbus(void *charger);

static inline u32 load32(const void *p)
{
    return *(const volatile u32 *)p;
}

static inline void *loadptr(const void *p)
{
    return *(void *const volatile *)p;
}

static inline int matches_9v(int mv)
{
    return mv >= 8250 && mv <= 9750;
}

/* Called at the normal PD high-VBUS ICL selection, before all stock clamps. */
u32 degas_pd_icl(void *charger, int measured_mv)
{
    u8 *info = charger;
    u32 fallback = load32(info + 4432);
    u8 cap[268];
    int done = 0, verifying = 1, mv = 0, ma = 0, pd_type;
    void *adapter, *private_info, *tcpc = (void *)0, *ports;
    int active_idx;
    u32 nr_ports, nr, selected, offered_ma, current_ma;

    if (!matches_9v(measured_mv))
        return fallback;
    adapter = loadptr(info + 1896);
    if (!adapter)
        return fallback;
    pd_type = adapter_dev_get_property(adapter, 1);
    if (pd_type != 3 && pd_type != 4)
        return fallback;
    if (usb_get_property(19, &done) || done != 1 ||
        usb_get_property(3, &verifying) || verifying != 0)
        return fallback;

    for (u32 i = 0; i < sizeof(cap); ++i)
        cap[i] = 0;
    if (adapter_dev_get_cap(adapter, 2, cap))
        return fallback;
    nr = cap[1];
    selected = cap[0]; /* pd_get_cap_pdo converts the 1-based TCPC index. */
    if (nr == 0 || nr > 10 || selected >= nr || cap[216 + selected] != 0)
        return fallback;
    if (load32(cap + 16 + 4 * selected) != 9000 ||
        load32(cap + 56 + 4 * selected) != 9000)
        return fallback;
    offered_ma = load32(cap + 96 + 4 * selected);
    if (offered_ma < 50 || offered_ma > 5000)
        return fallback;

    /* Same private ABI/idx_lock as factory pd_get_cap and pd_get_property. */
    private_info = loadptr((u8 *)adapter + 1512);
    if (!private_info)
        return fallback;
    mutex_lock((u8 *)private_info + 16);
    nr_ports = load32((u8 *)private_info + 64);
    active_idx = (int)load32((u8 *)private_info + 8);
    ports = loadptr((u8 *)private_info + 72);
    if (nr_ports >= 1 && nr_ports <= 8 && active_idx >= 0 &&
        (u32)active_idx < nr_ports && ports)
        tcpc = loadptr((u8 *)ports + sizeof(void *) * active_idx);
    mutex_unlock((u8 *)private_info + 16);
    if (!tcpc || tcpm_inquire_pd_contract(tcpc, &mv, &ma) ||
        mv != 9000 || ma < 50 || ma > 5000)
        return fallback;

    /* Recheck connection state after the reads; never renegotiate PD here. */
    if (adapter != loadptr(info + 1896) ||
        adapter_dev_get_property(adapter, 1) != pd_type ||
        !matches_9v(get_vbus(charger)) ||
        usb_get_property(19, &done) || done != 1 ||
        usb_get_property(3, &verifying) || verifying != 0)
        return fallback;
    current_ma = offered_ma;
    if (current_ma > (u32)ma)
        current_ma = (u32)ma;
    if (current_ma > 3000)
        current_ma = 3000; /* existing factory 5-V basic-charger ceiling */
    return (current_ma / 50) * 50000; /* mt6375 ICL step, round down */
}
