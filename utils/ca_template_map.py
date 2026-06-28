def build_ca_template_map(ldap_conn, base_dn):
    from utils.ldap_paginator import paginated_search
    ca_template_map = {}
    template_ca_map = {}
    entries = paginated_search(ldap_conn,
        f'CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,{base_dn}',
        '(objectClass=pKIEnrollmentService)',
        attributes=['cn', 'dNSHostName', 'certificateTemplates'])
    for entry in entries:
        ca_name = str(entry.cn)
        ca_host = str(entry.dNSHostName)
        templates = [str(t) for t in entry.certificateTemplates] if 'certificateTemplates' in entry and entry.certificateTemplates else []
        template_ca_map[ca_name] = {'host': ca_host, 'templates': templates}
        for tmpl in templates:
            if tmpl not in ca_template_map:
                ca_template_map[tmpl] = []
            ca_template_map[tmpl].append({'ca_name': ca_name, 'ca_host': ca_host})
    return ca_template_map, template_ca_map
