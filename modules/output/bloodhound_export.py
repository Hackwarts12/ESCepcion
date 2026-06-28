import json
from datetime import datetime
from typing import Dict, Any, List
import os

def export_bloodhound(ddcc_report: Any, domain: str, output_dir: str = ".") -> str:
    """
    Exports the DDCC graph to BloodHound v5 JSON format.
    Returns the path to the generated JSON file.
    """
    if not ddcc_report:
        return ""
        
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    filename = f"ESCepcion_BloodHound_{domain}_{timestamp}.json"
    filepath = os.path.join(output_dir, filename)

    nodes = []
    edges = []
    
    # Track added nodes to avoid duplicates
    added_nodes = set()
    
    def add_node(identifier: str, type_name: str, properties: Dict[str, Any]):
        if identifier not in added_nodes:
            nodes.append({
                "ObjectIdentifier": identifier,
                "ObjectType": type_name,
                "Properties": properties
            })
            added_nodes.add(identifier)

    def add_edge(source: str, target: str, edge_type: str):
        edges.append({
            "source": source,
            "target": target,
            "label": edge_type,
            "properties": {}
        })

    # We only generate elements from deterministic critical paths to avoid cluttering BH with noise
    paths = getattr(ddcc_report, "deterministic_critical_paths", []) or []
    
    for path in paths:
        # Source principal is a Base/User group (Group or User, we assume Group to be generic if not specified)
        # But in DDCC paths we have generic names like "Domain Users"
        source_id = path.start_principal.upper() + "@" + domain.upper()
        add_node(source_id, "Group", {"name": source_id, "domain": domain.upper()})
        
        for edge in getattr(path, "edges", []):
            template_name = getattr(edge, "template_name", "UnknownTemplate").upper() + "@" + domain.upper()
            target_identity = getattr(getattr(edge, "outcome", None), "target_identity", "UnknownTarget").upper() + "@" + domain.upper()
            
            # Add Template Node
            add_node(template_name, "CertTemplate", {"name": template_name, "domain": domain.upper()})
            
            # Add Target Node
            if target_identity != "UNKNOWNTARGET@" + domain.upper():
                add_node(target_identity, "Group", {"name": target_identity, "domain": domain.upper()})
            
            # Add Edges based on capability
            # If it's a template we assume the source can enroll
            add_edge(source_id, template_name, "Enroll")
            
            cap = getattr(edge, "capability", None)
            if cap:
                cap_name = getattr(cap, "name", "")
                if cap_name == "ESC1_VULN":
                    # Assume EnterpriseCA node exists (or add a dummy one)
                    ca_id = "ENTERPRISECA@" + domain.upper()
                    add_node(ca_id, "EnterpriseCA", {"name": ca_id, "domain": domain.upper()})
                    add_edge(template_name, ca_id, "ADCSESC1")
                elif cap_name == "ESC3_VULN":
                    ca_id = "ENTERPRISECA@" + domain.upper()
                    add_node(ca_id, "EnterpriseCA", {"name": ca_id, "domain": domain.upper()})
                    add_edge(template_name, ca_id, "ADCSESC3")
                elif cap_name == "ESC4_VULN":
                    add_edge(source_id, template_name, "ADCSESC4")
                    
            source_id = target_identity # For the next step in the chain
            
    # Certifried edges if added as descriptions (fallback logic for strings)
    # Since Certifried paths are added as strings, we parse them if present
    for path in paths:
        desc = getattr(path, "description", "")
        if "[CERTIFRIED PATH]" in desc:
            ca_id = "ENTERPRISECA@" + domain.upper()
            add_node(ca_id, "EnterpriseCA", {"name": ca_id, "domain": domain.upper()})
            add_node("DOMAIN_ADMIN@" + domain.upper(), "Group", {"name": "DOMAIN_ADMIN@" + domain.upper(), "domain": domain.upper()})
            add_edge("MACHINEACCOUNT@" + domain.upper(), ca_id, "ADCSESC1") # Approximation

    bh_data = {
        "meta": {
            "type": "adcs",
            "version": 6,
            "generator": "ESCepcion"
        },
        "nodes": nodes,
        "edges": edges
    }

    try:
        os.makedirs(output_dir, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(bh_data, f, indent=4)
        print(f" BloodHound JSON generado: {filepath}")
        return filepath
    except Exception as e:
        print(f"️ Error generando export BloodHound: {e}")
        return ""
