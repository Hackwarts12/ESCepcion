class ESCResult:
    VALID_STATUSES=['EXPLOITABLE','NEAR_MISS','POTENTIAL','INFORMATIVE','SAFE','NOT_SCANNED','ERROR']
    VALID_SEVERITIES=['Critical','High','Medium','Low','Info']
    VALID_CONFIDENCES=['LDAP_ONLY','LDAP_PLUS_ACL','LDAP_PLUS_REGISTRY','REGISTRY_DEEP_SCAN','RPC_CHECK','HTTP_PROBE','GRAPH_INFERENCE']
    VALID_METHODS=['LDAP','ACL','REGISTRY','RPC','HTTP','GRAPH']

    def __init__(self,esc_id,status,severity='Info',confidence='LDAP_ONLY',
                 validation_method='LDAP',affected_object=None,reason='',
                 evidence=None,blocking_controls=None,false_positive_risk='Low',
                 missing_validation=None,attack_chain=None,recommended_fix='',
                 requires_deep_scan=False,scope='Template',
                 certipy_equivalent=None,bloodhound_edge=None):
        if status not in self.VALID_STATUSES:
            raise ValueError(f'Status inválido: {status}')
        if status=='SAFE' and not evidence:
            raise ValueError('SAFE requiere evidence. Si no hay evidencia usar NOT_SCANNED.')
        self.esc_id=esc_id; self.status=status; self.severity=severity
        self.confidence=confidence; self.validation_method=validation_method
        self.affected_object=affected_object; self.reason=reason
        self.evidence=evidence or {}; self.blocking_controls=blocking_controls or []
        self.false_positive_risk=false_positive_risk
        self.missing_validation=missing_validation or []
        self.attack_chain=attack_chain or []; self.recommended_fix=recommended_fix
        self.requires_deep_scan=requires_deep_scan; self.scope=scope
        self.certipy_equivalent=certipy_equivalent; self.bloodhound_edge=bloodhound_edge

    def to_dict(self,evidence_level='standard'):
        base={'esc':self.esc_id,'status':self.status,'severity':self.severity,
              'confidence':self.confidence,'validation_method':self.validation_method,
              'affected_object':self.affected_object,'reason':self.reason,
              'blocking_controls':self.blocking_controls,
              'false_positive_risk':self.false_positive_risk,
              'missing_validation':self.missing_validation,
              'requires_deep_scan':self.requires_deep_scan,
              'scope':self.scope,'recommended_fix':self.recommended_fix}
        if evidence_level in('standard','full'):
            base['attack_chain']=self.attack_chain
            base['certipy_equivalent']=self.certipy_equivalent
            base['bloodhound_edge']=self.bloodhound_edge
        if evidence_level=='full':
            base['evidence']=self.evidence
        return base

    @staticmethod
    def not_scanned(esc_id,reason,manual_verification=None):
        return ESCResult(esc_id=esc_id,status='NOT_SCANNED',severity='Info',
            confidence='LDAP_ONLY',reason=reason,requires_deep_scan=True,
            missing_validation=[manual_verification or 'Requiere --deep-scan o verificación manual'],
            evidence={'placeholder':False})

    @staticmethod
    def placeholder_removed(esc_id):
        return ESCResult.not_scanned(esc_id=esc_id,
            reason=f'{esc_id} no implementado. Verificar manualmente.',
            manual_verification=f'Ver github.com/ly4k/Certipy/wiki para {esc_id}')
