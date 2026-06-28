def paginated_search(conn, search_base, search_filter, attributes, page_size=500, search_scope=None, controls=None):
    from ldap3 import SUBTREE
    scope = search_scope or SUBTREE
    all_entries = []
    
    kwargs = {'search_scope': scope, 'attributes': attributes, 'paged_size': page_size}
    if controls:
        kwargs['controls'] = controls
        
    conn.search(search_base, search_filter, **kwargs)
    all_entries.extend(list(conn.entries))
    cookie = _get_cookie(conn)
    while cookie:
        kwargs['paged_cookie'] = cookie
        conn.search(search_base, search_filter, **kwargs)
        all_entries.extend(list(conn.entries))
        cookie = _get_cookie(conn)
    return all_entries

def _get_cookie(conn):
    ctrl = conn.result.get('controls', {}).get('1.2.840.113556.1.4.319', {})
    if isinstance(ctrl, dict):
        return ctrl.get('value', {}).get('cookie', b'')
    return b''
