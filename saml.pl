:-module(saml,
         [saml_authenticate/3,
          trust_saml_idp/2]).


user:term_expansion(:-saml_service(ServiceProvider, Spec, Options),
                    [saml:saml_acs_path(ServiceProvider, ACSPath),
                     ( :-http_handler(MetadataPath, saml:saml_metadata(ServiceProvider, Options), [])),
                     ( :-http_handler(ACSPath, saml:saml_acs_handler(ServiceProvider, Options), []))]):-
        http_absolute_location(Spec, Root, []),
        atom_concat(Root, '/auth', ACSPath),
        atom_concat(Root, '/metadata.xml', MetadataPath).


%%          Configuration
%           Your code must define these 3 rules in order to act as a service provider
%           Additionally, you should declare saml_acs(ServiceProvide, PathSpec, Options) to declare some path on your server
%           that we can use for callbacks
:-multifile(saml:saml_certificate/4).
:-multifile(saml:saml_audience/2).
% End configuration


:-dynamic(saml:saml_idp/3).
:-dynamic(saml:saml_idp_certificate/4).
:-dynamic(saml:saml_idp_binding/4).
:-multifile(saml:saml_acs_path/2).

trust_saml_idp(ServiceProvider, MetadataFile):-
        setup_call_cleanup(open(MetadataFile, read, Stream),
                           load_structure(Stream, Metadata, [dialect(xmlns)]),
                           close(Stream)),
        (  memberchk(element('urn:oasis:names:tc:SAML:2.0:metadata':'EntitiesDescriptor', _, EntitiesDescriptor), Metadata)
        -> (  memberchk(element('urn:oasis:names:tc:SAML:2.0:metadata':'EntityDescriptor', EntityDescriptorAttributes, EntityDescriptor), EntitiesDescriptor),
              memberchk(element('urn:oasis:names:tc:SAML:2.0:metadata':'IDPSSODescriptor', IDPSSODescriptorAttributes, IDPSSODescriptor), EntityDescriptor)
           -> trust_saml_idp_descriptor(ServiceProvider, EntityDescriptorAttributes, IDPSSODescriptorAttributes, IDPSSODescriptor)
           ;  existence_error(idp_descriptor, MetadataFile)
           )
        ;  memberchk(element('urn:oasis:names:tc:SAML:2.0:metadata':'EntityDescriptor', EntityDescriptorAttributes, EntityDescriptor), Metadata),
           memberchk(element('urn:oasis:names:tc:SAML:2.0:metadata':'IDPSSODescriptor', IDPSSODescriptorAttributes, IDPSSODescriptor), EntityDescriptor)
        -> trust_saml_idp_descriptor(ServiceProvider, EntityDescriptorAttributes, IDPSSODescriptorAttributes, IDPSSODescriptor)
        ;  existence_error(idp_descriptor, MetadataFile)
        ).

trust_saml_idp_descriptor(ServiceProvider, EntityDescriptorAttributes, IDPSSODescriptorAttributes, IDPSSODescriptor):-
        memberchk(entityID=EntityID, EntityDescriptorAttributes),
        findall(CertificateUse-Certificate,
                idp_certificate(IDPSSODescriptor, CertificateUse, Certificate),
                Certificates),
        findall(binding(Binding, BindingInfo),
                ( member(element('urn:oasis:names:tc:SAML:2.0:metadata':'SingleSignOnService', SingleSignOnServiceAttributes, SingleSignOnService), IDPSSODescriptor),
                  process_saml_binding(SingleSignOnServiceAttributes, SingleSignOnService, Binding, BindingInfo)
                ),
                Bindings),
        (  Bindings == []
        -> existence_error(supported_binding, IDPSSODescriptor)
        ;  true
        ),
        (  memberchk('WantAuthnRequestsSigned'=true, IDPSSODescriptorAttributes)
        -> MustSign = true
        ;  MustSign = false
        ),

        retractall(saml_idp(ServiceProvider, EntityID, _)),
        retractall(saml_idp_binding(ServiceProvider, EntityID, _, _)),
        retractall(saml_idp_certificate(ServiceProvider, EntityID, _, _)),
        assert(saml_idp(ServiceProvider, EntityID, MustSign)),
        forall(member(CertificateUse-Certificate, Certificates),
               assert(saml_idp_certificate(ServiceProvider, EntityID, CertificateUse, Certificate))),
        forall(member(binding(Binding, BindingInfo), Bindings),
               assert(saml_idp_binding(ServiceProvider, EntityID, Binding, BindingInfo))).

idp_certificate(IDPSSODescriptor, CertificateUse, Certificate):-
        member(element('urn:oasis:names:tc:SAML:2.0:metadata':'KeyDescriptor', KeyDescriptorAttributes, KeyDescriptor), IDPSSODescriptor),
        memberchk(use=CertificateUse, KeyDescriptorAttributes),
        memberchk(element('http://www.w3.org/2000/09/xmldsig#':'KeyInfo', _, KeyInfo), KeyDescriptor),
        memberchk(element('http://www.w3.org/2000/09/xmldsig#':'X509Data', _, X509Data), KeyInfo),
        memberchk(element('http://www.w3.org/2000/09/xmldsig#':'X509Certificate', _, [X509CertificateData]), X509Data),
        normalize_space(string(TrimmedCertificate), X509CertificateData),
        format(string(CompleteCertificate), '-----BEGIN CERTIFICATE-----\n~s\n-----END CERTIFICATE-----', [TrimmedCertificate]),
        setup_call_cleanup(open_string(CompleteCertificate, StringStream),
                           load_certificate(StringStream, Certificate),
                           close(StringStream)).


process_saml_binding(SingleSignOnServiceAttributes, _, 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect', Location):-
        memberchk('Binding'='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect', SingleSignOnServiceAttributes), !,
        memberchk('Location'=Location, SingleSignOnServiceAttributes).

process_saml_binding(SingleSignOnServiceAttributes, _, 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST', Location):-
        memberchk('Binding'='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST', SingleSignOnServiceAttributes), !,
        memberchk('Location'=Location, SingleSignOnServiceAttributes).



form_authn_request(Request, ID, Destination, Date, ServiceProvider, ExtraElements, XML):-
        saml_acs_path(ServiceProvider, Path),
        select(path(_), Request, Request1),
        parse_url(ACSURL, [path(Path)|Request1]),
        SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol',
        SAML = 'urn:oasis:names:tc:SAML:2.0:assertion',
        XML = element(SAMLP:'AuthnRequest', ['ID'=ID,
                                             'Version'='2.0',
                                             'IssueInstant'=Date,
                                             'Destination'=Destination,
                                             'IsPassive'=false,
                                             'ProtocolBinding'='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                                             'AssertionConsumerServiceURL'=ACSURL],
                      [element(SAML:'Issuer', [], [ServiceProvider]),
                       element(SAMLP:'NameIDPolicy', ['AllowCreate'=true,
                                                      'Format'='urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'], [])|ExtraElements]).


http:authenticate(saml(ServiceProvider, IdentityProvider), Request, [user_id(UserId)]):-
        ( http_in_session(_),
          % FIXME: hard-coded
          http_session_data(saml('the-username', UserId))->
            true
        ; otherwise->
            saml_authenticate(ServiceProvider, IdentityProvider, Request)
        ).

saml_authenticate(ServiceProvider, IdentityProvider, Request):-
        memberchk(request_uri(RelayState), Request),
        get_xml_timestamp(Date),
        uuid(UUID),
        % the ID must start with a letter but the UUID may start with a number. Resolve this by prepending an 'a'
        atom_concat(a, UUID, ID),
        saml_idp(ServiceProvider, IdentityProvider, _MustSign),
        MustSign = true,
        XMLOptions = [header(false), layout(false)],
        % FIXME: This assumes the binding will be HTTP-Redirect, but we need to know the Destination to form the authn message
        saml_idp_binding(ServiceProvider, IdentityProvider, 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect', BaseURL),
        form_authn_request(Request, ID, BaseURL, Date, ServiceProvider, [], XML),
        with_output_to(string(XMLString), xml_write(current_output, XML, XMLOptions)),
        debug(saml, 'XML:~n~s~n', [XMLString]),
        setup_call_cleanup(new_memory_file(MemFile),
                           (setup_call_cleanup(open_memory_file(MemFile, write, MemWrite, [encoding(octet)]),
                                                (setup_call_cleanup(zopen(MemWrite, Write, [format(raw_deflate), level(9), close_parent(false)]),
	    							format(Write, '~s', [XMLString]),
	    							close(Write))
                                                ),
	    				    close(MemWrite)),
                             memory_file_to_atom(MemFile, SAMLRequestRaw)
                           ),
                           free_memory_file(MemFile)),
        base64(SAMLRequestRaw, SAMLRequest),
        debug(saml, 'Encoded request: ~w~n', [SAMLRequest]),
        % Form the URL
        (  saml_idp_binding(ServiceProvider, IdentityProvider, 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect', BaseURL)
        -> parse_url(BaseURL, Parts),
           (  MustSign == true
           -> saml_certificate(ServiceProvider, _, _, PrivateKey),
              saml_sign(PrivateKey, XMLString, SAMLRequest, RelayState, ExtraParameters)
           ;  ExtraParameters = []
           )
        ; domain_error(supported_binding, IdentityProvider)
        ),
        parse_url(IdPURL, [search(['SAMLRequest'=SAMLRequest, 'RelayState'=RelayState|ExtraParameters])|Parts]),
        format(user_error, 'Redirecting user to~n~w~n', [IdPURL]),
        http_redirect(moved_temporary, IdPURL, Request).

saml_simple_sign(PrivateKey, XMLString, _SAMLRequest, RelayState, ['SigAlg'=SigAlg,'Signature'=Signature]):-
	SigAlg = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
        format(string(DataToSign), 'SAMLRequest=~s&RelayState=~w&SigAlg=~w', [XMLString, RelayState, SigAlg]),
        debug(saml, 'Data to sign with HTTP-Redirect-SimpleSign:~n~s~n', [DataToSign]),
	sha_hash(DataToSign, Digest, [algorithm(sha1)]),
	rsa_sign(PrivateKey, Digest, RawSignature,
		 [ type(sha1),
		   encoding(octet)
		 ]),
        base64(RawSignature, Signature),
        debug(saml, 'Signature:~n~w~n', [Signature]).

saml_sign(PrivateKey, _XMLString, SAMLRequest, RelayState, ['SigAlg'=SigAlg,'Signature'=Signature]):-
        SigAlg = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
        parse_url_search(CodesToSign, ['SAMLRequest'=SAMLRequest, 'RelayState'=RelayState, 'SigAlg'=SigAlg]),
        string_codes(DataToSign, CodesToSign),
        debug(saml, 'Data to sign with HTTP-Redirect binding:~n~s~n', [DataToSign]),
	sha_hash(DataToSign, Digest, [algorithm(sha1)]),
	rsa_sign(PrivateKey, Digest, RawSignature,
		 [ type(sha1),
		   encoding(octet)
		 ]),
        base64(RawSignature, Signature),
        debug(saml, '~nSignature:~n~w~n', [Signature]).

saml_acs_handler(ServiceProvider, Options, Request):-
        debug(saml, 'Got a message back from IdP!~n', []),
	http_read_data(Request, PostedData, []),
        debug(saml, '~w~n', [PostedData]),
        memberchk('SAMLResponse'=Atom, PostedData),
        memberchk('RelayState'=Relay, PostedData),
        base64(RawData, Atom),
        atom_string(RawData, RawString),
        setup_call_cleanup(open_string(RawString, Stream),
			   load_structure(Stream, XML, [dialect(xmlns), keep_prefix(true)]),
                           close(Stream)),
        (  debugging(saml)
        -> xml_write(user_error, XML, [])
        ;  true
        ),
        process_saml_response(XML, ServiceProvider, fixme, Options),
        http_redirect(moved_temporary, Relay, Request).


propagate_ns([], _, []):- !.
propagate_ns([element(Tag, Attributes, Children)|Siblings],
             NS,
             [element(Tag, NewAttributes, NewChildren)|NewSiblings]):-
        !,
        merge_ns(NS, Attributes, NewAttributes, NewNS),
        propagate_ns(Children, NewNS, NewChildren),
        propagate_ns(Siblings, NS, NewSiblings).
propagate_ns([X|Siblings], NS, [X|NewSiblings]):-
        propagate_ns(Siblings, NS, NewSiblings).

merge_ns([xmlns:Prefix=Value|NS], Attributes, NewAttributes, NewNS):-
        (  select(xmlns:Prefix=NewValue, Attributes, A1)
        -> NewNS = [xmlns:Prefix=NewValue|T],
           NewAttributes = [xmlns:Prefix=NewValue|N]
        ;  A1 = Attributes,
           NewNS = [xmlns:Prefix=Value|T],
           NewAttributes = [xmlns:Prefix=Value|N]
        ),
        merge_ns(NS, A1, N, T).

merge_ns([], A, A, NS):-
        findall(xmlns:Prefix=Value, member(xmlns:Prefix=Value, A), NS).

process_saml_response(XML0, ServiceProvider, Callback, Options):-
        SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol',
        SAML = 'urn:oasis:names:tc:SAML:2.0:assertion',
        DS = 'http://www.w3.org/2000/09/xmldsig#',
        propagate_ns(XML0, [], XML),
        XML = [element(ns(_, SAMLP):'Response', _, Response)],
        % Response MAY  contain the following elements  : Issuer, Signature, Extensions
        % Response MAY  contain the following attributes: InResponseTo, Destination, Consent
        % Response MUST contain the following elements  : Status
        % Response MUST contain the following attributes: ID, IssueInstant, Version
	( memberchk(element(ns(_, SAMLP):'Status', _StatusAttributes, Status), Response)->
            % Status MUST contain a StatusCode element, and MAY contain a StatusMessage and or StatusDetail element
            ( memberchk(element(ns(_, SAMLP):'StatusCode', StatusCodeAttributes, _StatusCode), Status)->
                % StatusCode MUST contain a Value attribute
                ( memberchk('Value'=StatusCodeValue, StatusCodeAttributes)->
                    true
                % FIXME: Fix all these throw(atom) calls
                ; throw(illegal_saml_response)
                )
            ; throw(illegal_saml_response)
            )
        ; throw(illegal_saml_response)
	),
        (  memberchk(element(ns(_, SAML):'Issuer', _, [IssuerName]), Response)
	-> true
	;  IssuerName = {null}
	),

        ( member(element(ns(_, DS):'Signature', _, Signature), Response)->
            xmld_verify_signature(XML, Signature, Certificate, []),
            % Check that the certificate used to sign was one in the metadata
            (  saml_idp_certificate(ServiceProvider, IssuerName, signing, Certificate)
            -> true
            ;  domain_error(trusted_certificate, Certificate)
            )
        ; otherwise->
            % Warning: Message is not signed. Assertions may be though
            % FIXME: Determine a policy for handling this - if the SP wants them signed, we must make sure they are
            true
        ),

        ( StatusCodeValue == 'urn:oasis:names:tc:SAML:2.0:status:Success'->
            % The user has authenticated in some capacity. We can now open a session for them
            % Note that we cannot say anything ABOUT the user yet. That will come once we process the assertions
            http_open_session(_, [])
        ; StatusCodeValue == 'urn:oasis:names:tc:SAML:2.0:status:Requester'->
            throw(saml_rejected(requester))
        ; StatusCodeValue == 'urn:oasis:names:tc:SAML:2.0:status:Responder'->
            throw(saml_rejected(responder))
        ; StatusCodeValue == 'urn:oasis:names:tc:SAML:2.0:status:VersionMismatch'->
            throw(saml_rejected(version_mismatch))
        ; throw(saml_rejected(illegal_response))
        ),

        % Response MAY also contain 0..N of the following elements: Assertion, EncryptedAssertion.
        findall(AttributeName=AttributeValue,
                ( ( member(element(ns(SAMLPrefix, SAML):'Assertion', AssertionAttributes, Assertion), Response),
                    process_assertion(ServiceProvider, IssuerName, XML, AssertionAttributes, Assertion, AttributeName, AttributeValue))
                ; member(element(ns(SAMLPrefix, SAML):'EncryptedAssertion', _, EncryptedAssertion), Response),
                  decrypt_xml(EncryptedAssertion, DecryptedAssertion, saml:saml_key_callback(ServiceProvider), Options),
                  member(element(ns(_, SAML):'Assertion', AssertionAttributes, Assertion), DecryptedAssertion),
                  process_assertion(ServiceProvider, IssuerName, XML, AssertionAttributes, Assertion, AttributeName, AttributeValue)
                ),
                AcceptedAttributes),
        call(Callback, AcceptedAttributes).

process_assertion(ServiceProvider, _EntityID, Document, Attributes, Assertion, AttributeName, AttributeValue):-
        format(user_error, '~n~n~n', []),
        xml_write(user_error, element('Object', Attributes, Assertion), []),
        format(user_error, '~n~n~n', []),
        SAML = ns(_, 'urn:oasis:names:tc:SAML:2.0:assertion'),
	DS = ns(_, 'http://www.w3.org/2000/09/xmldsig#'),
        ( memberchk('ID'=_AssertionID, Attributes)->
            true
        ; throw(missing_assertion_id)
        ),
        % An Assertion MUST contain an Issuer, and MAY contain a Signature, Subject, Conditions, Advice, plus 0..N of the following:
        %   Statement
        %   AuthnStatement
        %   AuthzDecisionStatement
        %   AttributeStatement
        % It must also have all the following attributes, Version, ID, IssueInstant
        memberchk(element(SAML:'Issuer', _, [IssuerName]), Assertion),
        debug(saml, 'Received assertion from IdP ~w', [IssuerName]),
        ( member(element(DS:'Signature', _, Signature), Assertion)->
            xmld_verify_signature(Document, Signature, Certificate, []),
            % Check that the certificate used to sign was one in the metadata
            (  saml_idp_certificate(ServiceProvider, IssuerName, signing, Certificate)
            -> true
            ;  domain_error(trusted_certificate, Certificate)
            )
        ; otherwise->
            % Technically the standard allows this, but it seems like practically it would be useless?
            % Which part of the response SHOULD be signed? The entire thing or the assertions?
            true
            %throw(unsigned_response)
        ),
        ( memberchk(element(SAML:'Conditions', ConditionsAttributes, Conditions), Assertion)->
            % If conditions are present, we MUST check them. These can include arbitrary, user-defined conditions
            % and things like ProxyRestriction and OneTimeUse
            get_xml_timestamp(Date),
            ( memberchk('NotOnOrAfter'=Expiry, ConditionsAttributes)->
		Date @< Expiry
            ; true
            ),
            ( memberchk('NotBefore'=Expiry, ConditionsAttributes)->
                Date @> Expiry
            ; true
            ),
            forall(member(element(SAML:'Condition', ConditionAttributes, Condition), Conditions),
                   condition_holds(ConditionAttributes, Condition)),
            forall(member(element(SAML:'AudienceRestriction', _AudienceRestrictionAttributes, AudienceRestriction), Conditions),
		   ( member(element(SAML:'Audience', _, [Audience]), AudienceRestriction),
                     saml_audience(ServiceProvider, Audience)->
                       true
                   ; true %throw(illegal_audience) % FIXME: How do you determine the 'audience' exactly?
                   )),
            ( memberchk(element(SAML:'OneTimeUse', _, _), Conditions)->
                throw(one_time_use_not_supported)
            ; true
            ),
            ( memberchk(element(SAML:'ProxyRestriction', _, _), Conditions)->
                throw(proxy_restriction_not_supported)
            ; true
            )
        ; true
        ),
        % The Subject element is not mandatory. In the introduction to section 2, the specification states
        % "the <Subject> element is optional, and other specifications and profiles may utilize the SAML assertion
        % structure to make similar statements without specifying a subject, or possibly specifying the subject in an
        % alternate way"
        % However, 2.3.3 goes on to say that
        % "SAML itself defines no such statements, and an assertion without a subject has no defined meaning in this specification."
        % Specifically, 2.7.2, 2.7.3, 2.7.4 enumerate all the SAML-defined statements, and all of them say that the assertion MUST
        % contain a subject
        ( memberchk(element(SAML:'Subject', _, Subject), Assertion)->
            memberchk(element(SAML:'NameID', _, [IdPName]), Subject),
            debug(saml, 'Assertion is for subject ~w', [IdPName]),
            % Note that it is not mandatory for there to be any SubjectConfirmation in the message, however, since we must verify at least one
            % confirmation in order to trust that the subject has really associated with the IdP, a subject with no confirmations is useless anyway
            ( member(element(SAML:'SubjectConfirmation', SubjectConfirmationAttributes, SubjectConfirmation), Subject),
              subject_confirmation_is_valid(SubjectConfirmationAttributes, SubjectConfirmation)->
                debug(saml, 'Subject is confirmed', [])
            ; debug(saml, 'No valid subject confirmation could be found', []),
              throw(no_subject_confirmation)
            )
        ; throw(not_supported(assertion_without_subject))
        ),
        !,
        memberchk(element(SAML:'AttributeStatement', _, AttributeStatement), Assertion),
        member(element(SAML:'Attribute', AttributeAttributes, Attribute), AttributeStatement),
        memberchk('Name'=AttributeName, AttributeAttributes),
        memberchk(element(SAML:'AttributeValue', _, [AttributeValue]), Attribute).

process_assertion(_Attributes, _Assertion, _, _, _, _):-
	debug(saml, 'Warning: Assertion was not valid', []).

condition_holds(_ConditionAttributes, _Condition):-
        throw(conditions_not_implemented).

get_xml_timestamp(Date):-
        get_time(Time),
        stamp_date_time(Time, date(Y, M, D, HH, MM, SSF, _, 'UTC', _), 'UTC'),
        SS is integer(SSF),
        format(atom(Date), '~w-~|~`0t~w~2+-~|~`0t~w~2+T~|~`0t~w~2+:~|~`0t~w~2+:~|~`0t~w~2+Z', [Y,M,D,HH,MM,SS]).


subject_confirmation_is_valid(SubjectConfirmationAttributes, SubjectConfirmation):-
	SAML = ns(_, 'urn:oasis:names:tc:SAML:2.0:assertion'),
        memberchk('Method'='urn:oasis:names:tc:SAML:2.0:cm:bearer', SubjectConfirmationAttributes), % this is the only method we support
        memberchk(element(SAML:'SubjectConfirmationData', Attributes, _SubjectConfirmationData), SubjectConfirmation),
        get_xml_timestamp(Date),
        ( memberchk('NotOnOrAfter'=Expiry, Attributes)->
            Date @< Expiry
        ; true
        ),
        ( memberchk('NotBefore'=Expiry, Attributes)->
            Date @> Expiry
        ; true
        ),
        ( memberchk('InResponseTo'=_InResponseTo, Attributes)->
            % FIXME: Check that we sent the message, somehow?
            true
        ; true
        ),
        ( memberchk('Recipient'=_Recipient, Attributes)->
            % FIXME: Check that this is us, somehow?
            true
        ; true
        ),
        % FIXME: We can also have other arbitrary elements and attributes in here for user-defined extensions. These are ignored.
        true.

saml_key_callback(ServiceProvider, certificate, KeyHint, Key):-
	saml_certificate(ServiceProvider, KeyHint, _, Key), !.


saml_metadata(ServiceProvider, _Options, Request):-
	MD = 'urn:oasis:names:tc:SAML:2.0:metadata',
        DS = 'http://www.w3.org/2000/09/xmldsig#',
        saml_certificate(ServiceProvider, _X509Certificate, X509Certificate, _PrivateKey),

        % All of this should be configurable, eventually?
        EncryptionMethod = 'http://www.w3.org/2009/xmlenc11#rsa-oaep',
        NameIDFormat = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
	ACSBinding = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',

        parse_url(RequestURL, Request),
        http_absolute_location('./auth', ACSLocation, [relative_to(RequestURL)]),
	string_concat("-----BEGIN CERTIFICATE-----\n", X509CertificateWithoutHeader, X509Certificate),
	string_concat(PresentableCertificate, "-----END CERTIFICATE-----\n", X509CertificateWithoutHeader),
        format(current_output, 'Content-type: text/xml~n~n', []),
        XML = [element(MD:'EntitiesDescriptor', [], [EntityDescriptor])],
        EntityDescriptor = element(MD:'EntityDescriptor', [entityID=ServiceProvider, 'AuthnRequestsSigned'=true], [SPSSODescriptor]),
        SPSSODescriptor = element(MD:'SPSSODescriptor', [protocolSupportEnumeration='urn:oasis:names:tc:SAML:2.0:protocol'], [EncryptionKeyDescriptor,
                                                                                                                              SigningKeyDescriptor,
                                                                                                                              element(MD:'NameIDFormat', [], [NameIDFormat]),
                                                                                                                              AssertionConsumerService]),
        EncryptionKeyDescriptor = element(MD:'KeyDescriptor', [use=encryption], [KeyInfo,
                                                                                 element(MD:'EncryptionMethod', ['Algorithm'=EncryptionMethod], [])]),
        SigningKeyDescriptor = element(MD:'KeyDescriptor', [use=signing], [KeyInfo,
                                                                              element(MD:'EncryptionMethod', ['Algorithm'=EncryptionMethod], [])]),

        KeyInfo = element(DS:'KeyInfo', [], [X509Data]),
        X509Data = element(DS:'X509Data', [], [element(DS:'X509Certificate', [], [PresentableCertificate])]),
        AssertionConsumerService = element(MD:'AssertionConsumerService', [index='0', isDefault=true, 'Binding'=ACSBinding, 'Location'=ACSLocation], []),
        xml_write(current_output, XML, []).

