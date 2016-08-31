:-module(saml,
	 [saml_metadata/2]).

% For this to work, you must have a web server running on port 8082, a signed certificate in /tmp/cert.pem with key in /tmp/key.pem and
% upload the output of saml_metadata(trime2, X) to https://www.testshib.org/register.html to install the metadata.
% You also need a VERY new version of SWI-Prolog, and the xml-enc, xmldsig and c14n modules

% See saml-test.pl for a framework to load all this.
% Note that this is currently just a proof of concept!

user:term_expansion(:-saml_acs(ServiceProvider, Path, Options),
		    [saml_acs_path(ServiceProvider, Path),
		     ( :-http_handler(Path, saml:saml_acs_handler(ServiceProvider, Options), []))]).



%%%		    Configuration

:-http_handler(root('saml/foo'), some_saml_resource, [authentication(saml(trime2))]).

some_saml_resource(Request):-
        memberchk(user_id(UserId), Request),
        format(current_output, 'Content-type: text/html~n~nHello, ~w', [UserId]).




:-saml_acs(trime2, root('saml/xacs'), []).
is_correct_audience(trime2, _).
certificate_is_trusted(trime2, _IssuerName, _Certificate):- true.
saml_idp(trime2, 'https://idp.testshib.org/idp/profile/SAML2/Redirect/SSO').

% Ideally,  this would be saml_certificate/3 and PEMData could be formed from Certificate via write_certificate
% but in practise recovering the X509* from the prolog term is impossible
saml_certificate(trime2, Certificate, PEMData, PrivateKey):-
	% For testing purposes only. This is obviously horrifically inefficient!
	setup_call_cleanup(open('/tmp/key.pem', read, Stream),
                           load_private_key(Stream, '', PrivateKey),
			   close(Stream)),
	setup_call_cleanup(open('/tmp/cert.pem', read, Stream2),
			   read_string(Stream2, _, PEMData),
			   close(Stream2)),
	setup_call_cleanup(open_string(PEMData, Stream3),
			   load_certificate(Stream3, Certificate),
			   close(Stream3)).


saml_key_callback(ServiceProvider, certificate, KeyHint, Key):-
	saml_certificate(ServiceProvider, KeyHint, _, Key), !.



% End configuration




http:authenticate(saml(ServiceProvider), Request, [user_id(UserId)]):-
        ( http_in_session(_),
          http_session_data(saml('urn:oid:2.5.4.42', UserId))->
            true
        ; otherwise->
            SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol',
            SAML = 'urn:oasis:names:tc:SAML:2.0:assertion',
            memberchk(request_uri(RelayState), Request),
            get_xml_timestamp(Date),
            uuid(UUID),
            format(atom(ID), 'a~w', [UUID]),
            XML = element(SAMLP:'AuthnRequest', ['ID'=ID,
                                                 'Version'='2.0',
                                                 'IssueInstant'=Date,
                                                 'AssertionConsumerServiceIndex'=0,
						 'AttributeConsumingServiceIndex'=0], [element(SAML:'Issuer', [], [ServiceProvider]),
                                                                                       element(SAML:'NameIDPolicy', ['AllowCreate'=true,
                                                                                                                     'Format'='urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'], [])]),
            setup_call_cleanup(new_memory_file(MemFile),
                               (setup_call_cleanup(open_memory_file(MemFile, write, MemWrite, [encoding(octet)]),
                                                    (setup_call_cleanup(zopen(MemWrite, Write, [format(raw_deflate), level(9), close_parent(false)]),
                                                                         xml_write(Write, XML, [header(false)]),
                                                                         close(Write))
                                                    ),
                                                    close(MemWrite)),
                                 memory_file_to_atom(MemFile, SAMLRequestRaw)
                               ),
                               free_memory_file(MemFile)),
            base64(SAMLRequestRaw, SAMLRequest),
            format(user_error, '~w~n', [SAMLRequest]),
	    % Form the URL
	    saml_idp(ServiceProvider, BaseURL),
	    parse_url(BaseURL, Parts),
            parse_url(IdPURL, [search(['SAMLRequest'=SAMLRequest,'RelayState'=RelayState])|Parts]),
	    http_redirect(moved_temporary, IdPURL, Request)
        ).



saml_acs_handler(ServiceProvider, Options, Request):-
	http_read_data(Request, PostedData, []),
        memberchk('SAMLResponse'=Atom, PostedData),
        memberchk('RelayState'=Relay, PostedData),
        base64(RawData, Atom),
        atom_string(RawData, RawString),
        setup_call_cleanup(open_string(RawString, Stream),
			   load_structure(Stream, XML, [dialect(xmlns), keep_prefix(true)]),
                           close(Stream)),
	xml_write(user_error, XML, []),
	process_response(XML, ServiceProvider, Options),
        http_redirect(moved_temporary, Relay, Request).


process_response(XML, ServiceProvider, Options):-
	SAMLP = ns(_, 'urn:oasis:names:tc:SAML:2.0:protocol'),
	SAML = ns(_, 'urn:oasis:names:tc:SAML:2.0:assertion'),
	DS = ns(_, 'http://www.w3.org/2000/09/xmldsig#'),
	XML = [element(SAMLP:'Response', _ResponseAttributes, Response)],
        % Response MAY  contain the following elements  : Issuer, Signature, Extensions
        % Response MAY  contain the following attributes: InResponseTo, Destination, Consent
        % Response MUST contain the following elements  : Status
        % Response MUST contain the following attributes: ID, IssueInstant, Version
	( memberchk(element(SAMLP:'Status', _StatusAttributes, Status), Response)->
            % Status MUST contain a StatusCode element, and MAY contain a StatusMessage and or StatusDetail element
	    ( memberchk(element(SAMLP:'StatusCode', StatusCodeAttributes, _StatusCode), Status)->
                % StatusCode MUST contain a Value attribute
                ( memberchk('Value'=StatusCodeValue, StatusCodeAttributes)->
                    true
                ; throw(illegal_saml_response)
                )
            ; throw(illegal_saml_response)
            )
        ; throw(illegal_saml_response)
	),
	(  memberchk(element(SAML:'Issuer', _, [IssuerName]), Response)
	-> true
	;  IssuerName = {null}
	),

	( member(element(DS:'Signature', _, Signature), Response)->
	    xmld_verify_signature(Signature, Certificate, []),
	    certificate_is_trusted(ServiceProvider, IssuerName, Certificate)
        ; otherwise->
            % Warning: Message is not signed. Assertions may be though
            true
        ),

	( StatusCodeValue == 'urn:oasis:names:tc:SAML:2.0:status:Success'->
            % The user has authenticated in some capacity. We can now open a session for them
            % Note that we cannot say anything ABOUT the user yet. That will come once we process the assertions
	    %writeln(open_session)
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
	forall(member(element(SAML:'Assertion', AssertionAttributes, Assertion), Response),
	       process_assertion(ServiceProvider, AssertionAttributes, Assertion)),
	forall(member(element(SAML:'EncryptedAssertion', _, EncryptedAssertion), Response),
	       ( decrypt_xml(EncryptedAssertion, DecryptedAssertion, saml:saml_key_callback(ServiceProvider), Options),
		 forall(member(element(SAML:'Assertion', AssertionAttributes, Assertion), DecryptedAssertion),
			process_assertion(ServiceProvider, AssertionAttributes, Assertion)))
	      ).


process_assertion(ServiceProvider, Attributes, Assertion):-
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
	    xmld_verify_signature(Signature, Certificate, []),
	    certificate_is_trusted(ServiceProvider, IssuerName, Certificate)
        ; otherwise->
            % Technically the standard allows this, but it seems like practically it would be useless?
            throw(unsigned_response)
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
		     is_correct_audience(ServiceProvider, Audience)->
                       true
                   ; throw(illegal_audience)
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
        ( memberchk(element(SAML:'AttributeStatement', _, AttributeStatement), Assertion)->
            forall(member(element(SAML:'Attribute', AttributeAttributes, Attribute), AttributeStatement),
                   ( memberchk('Name'=Name, AttributeAttributes),
                     memberchk(element(SAML:'AttributeValue', _, [Value]), Attribute),
                     Key = saml(Name, Value),
                     http_session_assert(Key)
                   ))
        ; true
	).

process_assertion(_Attributes, _Assertion):-
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




saml_metadata(ServiceProvider, Metadata):-
	MD = 'urn:oasis:names:tc:SAML:2.0:metadata',
	DS = 'http://www.w3.org/2000/09/xmldsig#',

	saml_certificate(ServiceProvider, _X509Certificate, X509Certificate, _PrivateKey),
	% FIXME: All of this should be configurable. Escpecially URLParts.
        EncryptionMethod = 'http://www.w3.org/2009/xmlenc11#rsa-oaep',
        NameIDFormat = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
	ACSBinding = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',

	URLParts = [host(localhost), port(8082), protocol(http)],

	% For the ACS URL out of the metadata
	saml_acs_path(ServiceProvider, Path),
	http_absolute_location(Path, AbsolutePath, []),
	parse_url(ACSLocation, [path(AbsolutePath)|URLParts]),
	string_concat("-----BEGIN CERTIFICATE-----\n", X509CertificateWithoutHeader, X509Certificate),
	string_concat(PresentableCertificate, "-----END CERTIFICATE-----\n", X509CertificateWithoutHeader),
	Metadata = [element(MD:'EntityDescriptor', [entityID=ServiceProvider], [element(MD:'SPSSODescriptor', [protocolSupportEnumeration='urn:oasis:names:tc:SAML:2.0:protocol'], [element(MD:'KeyDescriptor', [use=encryption], [element(DS:'KeyInfo', [], [element(DS:'X509Data', [], [element(DS:'X509Certificate', [], [PresentableCertificate])])]),
																												   element(MD:'EncryptionMethod', ['Algorithm'=EncryptionMethod], [])]),
																						    element(MD:'NameIDFormat', [], [NameIDFormat]),
																						    element(MD:'AssertionConsumerService', [index='0', isDefault=true, 'Binding'=ACSBinding, 'Location'=ACSLocation], [])])])].