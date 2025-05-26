# Function Index

*Searchable reference of all functions and methods*

================================================================================
FUNCTION INDEX - SEARCHABLE REFERENCE
================================================================================


🔧 ANALYZERS
--------------------------------------------------

  __init__(self, image_data: bytes, verbose: bool, state: Optional['State'])
    📍 analyzers.image_analyzer.AdvancedSteganographyExtractor

  _bits_to_bytes(self, bits: List[int]) -> bytes
    📍 analyzers.image_analyzer.AdvancedSteganographyExtractor
    💡 Convert list of bits to bytes

  _detect_file_type(data: bytes) -> Optional[str]
    📍 analyzers.image_analyzer
    💡 Detect file type from binary data

  _extract_bits_advanced(self, bit_plane: int, channel: int, bit_order: str, scan_order: str, filter_func: Optional[Callable]) -> List[int]
    📍 analyzers.image_analyzer.AdvancedSteganographyExtractor
    💡 Advanced bit extraction with multiple parameters

  _generate_search_query(state: State) -> str
    📍 analyzers.web_analyzer

  _generate_task_description(state: State) -> str
    📍 analyzers.code_analyzer

  _get_scan_coordinates(self, width: int, height: int, scan_order: str) -> List[Tuple[int, int]]
    📍 analyzers.image_analyzer.AdvancedSteganographyExtractor
    💡 Generate pixel coordinates based on scan order

  _get_special_filter(self, filter_type: str) -> Callable
    📍 analyzers.image_analyzer.AdvancedSteganographyExtractor
    💡 Get special pixel filter function

  _is_fibonacci(self, n: int) -> bool
    📍 analyzers.image_analyzer.AdvancedSteganographyExtractor
    💡 Check if number is Fibonacci

  _is_meaningful_data(self, data: bytes) -> bool
    📍 analyzers.image_analyzer.AdvancedSteganographyExtractor
    💡 Check if extracted data appears meaningful

  _is_prime(self, n: int) -> bool
    📍 analyzers.image_analyzer.AdvancedSteganographyExtractor
    💡 Check if number is prime

  _spiral_coordinates(self, width: int, height: int) -> List[Tuple[int, int]]
    📍 analyzers.image_analyzer.AdvancedSteganographyExtractor
    💡 Generate coordinates in spiral pattern

  _verify_solution(solution: str) -> bool
    📍 analyzers.code_analyzer

  _zigzag_coordinates(self, width: int, height: int) -> List[Tuple[int, int]]
    📍 analyzers.image_analyzer.AdvancedSteganographyExtractor
    💡 Generate coordinates in zigzag pattern

  address_to_message(addresses: List[str]) -> Optional[str]
    📍 analyzers.blockchain_analyzer

  analyze_atbash_cipher(state: State, text: str) -> None
    📍 analyzers.cipher_analyzer

  analyze_baconian_cipher(state: State, text: str) -> None
    📍 analyzers.cipher_analyzer

  analyze_base32(state: State, text: str) -> None
    📍 analyzers.encoding_analyzer

  analyze_base64(state: State, text: str, is_related, filename) -> None
    📍 analyzers.encoding_analyzer

  analyze_base85_ascii85(state: State, text: str) -> None
    📍 analyzers.encoding_analyzer

  analyze_binary(state: State, text: str) -> None
    📍 analyzers.encoding_analyzer

  @register_analyzer('binary_analyzer'), @analyzer_compatibility(requires_binary=True) analyze_binary(state: State) -> State
    📍 analyzers.binary_analyzer

  analyze_binary_for_wallets(binary_data: bytes) -> List[Tuple[str, str]]
    📍 analyzers.crypto_analyzer

  @register_analyzer('binwalk'), @analyzer_compatibility(requires_binary=True) analyze_binwalk(state: State) -> State
    📍 analyzers.binwalk_analyzer

  @register_analyzer('blockchain_analyzer'), @analyzer_compatibility() analyze_blockchain(state: State, hex_strings, metadata) -> State
    📍 analyzers.blockchain_analyzer

  analyze_caesar_cipher(state: State, text: str, is_related, filename) -> None
    📍 analyzers.cipher_analyzer

  analyze_character_distribution(state: State, text: str) -> None
    📍 analyzers.text_analyzer

  @register_analyzer('cipher_analyzer'), @analyzer_compatibility(requires_text=True) analyze_ciphers(state: State, cipher_type: str, input_data: str) -> State
    📍 analyzers.cipher_analyzer

  @register_analyzer('code_analyzer'), @analyzer_compatibility(file_types=['*'], binary=True, text=True) analyze_code(state: State, task_description: str, **kwargs) -> State
    📍 analyzers.code_analyzer

  @register_analyzer('crypto_analyzer'), @analyzer_compatibility(requires_text=True) analyze_crypto(state: State) -> State
    📍 analyzers.crypto_analyzer

  @register_analyzer('cryptographic_analyzer'), @analyzer_compatibility(requires_text=True) analyze_cryptographic(state: State) -> State
    📍 analyzers.cryptographic_analyzer

  analyze_cryptographic_patterns(state: State, text: str) -> None
    📍 analyzers.text_pattern_analyzer

  analyze_decimal(state: State, text: str) -> None
    📍 analyzers.encoding_analyzer

  @register_analyzer('encoding_analyzer'), @analyzer_compatibility(requires_text=True) analyze_encodings(state: State) -> State
    📍 analyzers.encoding_analyzer

  analyze_entropy(state: State, data: bytes) -> None
    📍 analyzers.binary_analyzer

  analyze_ethereum_address(address: str) -> Optional[str]
    📍 analyzers.crypto_analyzer

  @register_analyzer('analyze_ethereum_data') analyze_ethereum_data(state: State) -> State
    📍 analyzers.blockchain_analyzer

  analyze_grayscale_image(state: State, image) -> None
    📍 analyzers.image_analyzer
    💡 Analyze grayscale image for suspicious patterns

  analyze_hex(state: State, text: str, is_related, filename) -> None
    📍 analyzers.encoding_analyzer

  analyze_html_entities(state: State, text: str) -> None
    📍 analyzers.encoding_analyzer

  @register_analyzer('advanced_steganography'), @register_analyzer('steganography_analyzer'), @register_analyzer('steganography_extractor'), @register_analyzer('image_analyzer'), @analyzer_compatibility(requires_binary=True) analyze_image(state: State, **kwargs) -> State
    📍 analyzers.image_analyzer

  analyze_image_metadata(state: State, image) -> None
    📍 analyzers.image_analyzer
    💡 Extract and analyze image metadata

  analyze_image_with_opencv(state: State) -> State
    📍 analyzers.image_analyzer
    💡 Fallback analysis using OpenCV when vision API is not available

  analyze_leetspeak(state: State, text: str) -> None
    📍 analyzers.encoding_analyzer

  analyze_line_patterns(state: State, text: str) -> None
    📍 analyzers.text_analyzer

  analyze_morse_code(state: State, text: str) -> None
    📍 analyzers.encoding_analyzer

  analyze_palette_image(state: State, image) -> None
    📍 analyzers.image_analyzer
    💡 Analyze palette-based image

  analyze_positional_patterns(state: State, text: str) -> None
    📍 analyzers.text_pattern_analyzer

  analyze_potential_encodings(state: State, text: str) -> None
    📍 analyzers.text_analyzer

  analyze_quoted_printable(state: State, text: str) -> None
    📍 analyzers.encoding_analyzer

  analyze_rail_fence_cipher(state: State, text: str) -> None
    📍 analyzers.cipher_analyzer

  analyze_regex_patterns(state: State, text: str) -> None
    📍 analyzers.text_pattern_analyzer

  analyze_repeating_patterns(state: State, text: str) -> None
    📍 analyzers.text_pattern_analyzer

  analyze_rgb_image(state: State, image) -> None
    📍 analyzers.image_analyzer
    💡 Analyze RGB image for suspicious patterns

  analyze_rot13(state: State, text: str) -> None
    📍 analyzers.encoding_analyzer

  analyze_smart_contract(contract_type: str, code: str) -> Optional[str]
    📍 analyzers.crypto_analyzer

  analyze_substitution_cipher(state: State, text: str) -> None
    📍 analyzers.cipher_analyzer

  @register_analyzer('text_analyzer'), @analyzer_compatibility(requires_text=True) analyze_text(state: State) -> State
    📍 analyzers.text_analyzer

  @register_analyzer('text_pattern_analyzer'), @analyzer_compatibility(requires_text=True) analyze_text_patterns(state: State) -> State
    📍 analyzers.text_pattern_analyzer

  analyze_transposition_cipher(state: State, text: str) -> None
    📍 analyzers.cipher_analyzer

  analyze_url_encoding(state: State, text: str) -> None
    📍 analyzers.encoding_analyzer

  analyze_uuencoding(state: State, text: str) -> None
    📍 analyzers.encoding_analyzer

  analyze_vigenere_cipher(state: State, text: str) -> None
    📍 analyzers.cipher_analyzer

  @register_analyzer('vision_analyzer'), @analyzer_compatibility(file_types=['png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff', 'webp'], binary=True, text=False) analyze_vision(state: State, provider, api_key, model, max_image_size, **kwargs) -> State
    📍 analyzers.vision_analyzer

  @register_analyzer('web_analyzer'), @analyzer_compatibility(file_types=['*'], binary=True, text=True) analyze_web(state: State, query: str, **kwargs) -> State
    📍 analyzers.web_analyzer

  analyze_with_pil(state: State) -> None
    📍 analyzers.image_analyzer
    💡 Analyze image using PIL: dimensions, mode, format, color stats, metadata

  analyze_word_patterns(state: State, text: str) -> None
    📍 analyzers.text_analyzer

  analyze_xor_cipher(state: State, text: str) -> None
    📍 analyzers.cipher_analyzer

  analyzer_compatibility(**kwargs)
    📍 analyzers.base

  atbash_decode(text: str) -> str
    📍 analyzers.cipher_analyzer

  attempt_hash_crack(hash_value: str, hash_type: str) -> Optional[str]
    📍 analyzers.crypto_analyzer

  caesar_decode(text: str, shift: int) -> str
    📍 analyzers.cipher_analyzer

  check_basic_lsb_steganography(state: State) -> None
    📍 analyzers.image_analyzer
    💡 Basic LSB steganography detection

  check_embedded_files(state: State) -> None
    📍 analyzers.image_analyzer
    💡 Check for files embedded within the image

  @register_analyzer('check_encoded_messages') check_encoded_messages(state: State) -> State
    📍 analyzers.blockchain_analyzer

  check_for_embedded_files(state: State, data: bytes) -> None
    📍 analyzers.binary_analyzer

  check_for_hidden_text(state: State, data: bytes) -> None
    📍 analyzers.binary_analyzer

  check_for_unusual_patterns(state: State, data: bytes) -> None
    📍 analyzers.binary_analyzer

  decode_transaction_data(data: str) -> Optional[str]
    📍 analyzers.blockchain_analyzer

  @register_analyzer('detect_addresses') detect_addresses(state: State) -> State
    📍 analyzers.blockchain_analyzer

  detect_bit_shift(data: bytes) -> int
    📍 analyzers.binary_analyzer

  detect_crypto_addresses(text: str) -> List[str]
    📍 analyzers.blockchain_analyzer

  detect_xor(data: bytes) -> int
    📍 analyzers.binary_analyzer

  extract_frequency_domain(self) -> Dict[str, bytes]
    📍 analyzers.image_analyzer.AdvancedSteganographyExtractor
    💡 Extract data from DCT/DFT frequency domain

  extract_lsb_channel(image, channel: int) -> Optional[str]
    📍 analyzers.image_analyzer
    💡 Extract LSB bits from a specific channel

  extract_multi_bitplane_advanced(self) -> Dict[str, bytes]
    📍 analyzers.image_analyzer.AdvancedSteganographyExtractor
    💡 Extract data from multiple bit planes with advanced configurations

  extract_png_chunks_advanced(self) -> Dict[str, bytes]
    📍 analyzers.image_analyzer.AdvancedSteganographyExtractor
    💡 Advanced PNG chunk analysis

  extract_prime_fibonacci_patterns(self) -> Dict[str, bytes]
    📍 analyzers.image_analyzer.AdvancedSteganographyExtractor
    💡 Extract data using prime and Fibonacci pixel indexing

  extract_text_from_image(state: State) -> None
    📍 analyzers.image_analyzer
    💡 Extract ASCII/UTF-8 strings from raw image data

  extract_wallet_address(wallet_type: str, wallet_content: str) -> Optional[str]
    📍 analyzers.crypto_analyzer

  extract_xor_patterns(self) -> Dict[str, bytes]
    📍 analyzers.image_analyzer.AdvancedSteganographyExtractor
    💡 Extract data with XOR pattern analysis

  find_interesting_transactions(transactions: List[Dict[str, Any]]) -> List[Dict[str, Any]]
    📍 analyzers.blockchain_analyzer

  find_repeating_patterns(data: bytes, min_length, max_length) -> bytes
    📍 analyzers.binary_analyzer

  find_repeating_sequences(text: str, min_length, max_length) -> dict
    📍 analyzers.cipher_analyzer

  find_strings(data: bytes, min_length: int) -> List[Tuple[str, int]]
    📍 analyzers.image_analyzer
    💡 Find ASCII strings in binary data

  find_strings(data: bytes, min_length) -> list
    📍 analyzers.binary_analyzer

  find_transactions_with_data(transactions: List[Dict[str, Any]]) -> List[Dict[str, Any]]
    📍 analyzers.blockchain_analyzer

  get_all_analyzers() -> Dict[str, Callable]
    📍 analyzers.base

  get_analyzer(name: str) -> Callable
    📍 analyzers.base

  get_bitcoin_op_return(address: str) -> List[str]
    📍 analyzers.blockchain_analyzer

  get_compatible_analyzers(state) -> List[str]
    📍 analyzers.base

  get_contract_code(address: str) -> Optional[str]
    📍 analyzers.blockchain_analyzer

  get_ethereum_transactions(address: str) -> List[Dict[str, Any]]
    📍 analyzers.blockchain_analyzer

  has_pattern_in_lsb(bit_string: str) -> bool
    📍 analyzers.image_analyzer
    💡 Check if LSB bit string has suspicious patterns

  identify_and_decode_base64(text: str) -> List[Tuple[str, str]]
    📍 analyzers.crypto_analyzer

  identify_and_decode_hex(text: str) -> List[Tuple[str, str]]
    📍 analyzers.crypto_analyzer

  identify_blockchain_addresses(text: str) -> List[Tuple[str, str]]
    📍 analyzers.crypto_analyzer

  identify_file_type(state: State, data: bytes) -> None
    📍 analyzers.binary_analyzer

  identify_file_type_from_data(data: bytes) -> str
    📍 analyzers.binary_analyzer

  identify_hashes(text: str) -> List[Tuple[str, str]]
    📍 analyzers.crypto_analyzer

  identify_pgp_elements(text: str) -> List[Tuple[str, str]]
    📍 analyzers.crypto_analyzer

  identify_private_keys(text: str) -> List[Tuple[str, str]]
    📍 analyzers.crypto_analyzer

  identify_smart_contracts(text: str) -> List[Tuple[str, str]]
    📍 analyzers.crypto_analyzer

  identify_wallet_files(text: str) -> List[Tuple[str, str]]
    📍 analyzers.crypto_analyzer

  is_bitcoin_address(address: str) -> bool
    📍 analyzers.blockchain_analyzer

  is_contract_address(address: str) -> bool
    📍 analyzers.blockchain_analyzer

  is_ethereum_address(address: str) -> bool
    📍 analyzers.blockchain_analyzer

  is_likely_hash(hex_string: str) -> bool
    📍 analyzers.crypto_analyzer

  is_likely_mnemonic(phrase: str) -> bool
    📍 analyzers.crypto_analyzer

  lsb_bits_to_text(bit_string: str) -> Optional[str]
    📍 analyzers.image_analyzer
    💡 Convert LSB bit string to text

  main()
    📍 test_analyzer

  rail_fence_decode(text: str, rails: int) -> str
    📍 analyzers.cipher_analyzer

  register_analyzer(name)
    📍 analyzers.base

  rot13_char(c: str) -> str
    📍 analyzers.encoding_analyzer

  score_english_text(text: str) -> float
    📍 analyzers.cipher_analyzer

  simple_substitution_decode(text: str, mapping: dict) -> str
    📍 analyzers.cipher_analyzer

  vigenere_decode(text: str, key: str) -> str
    📍 analyzers.cipher_analyzer

🔧 CORE MODULES
--------------------------------------------------

  __init__(self, output_dir: str, results_dir: str)
    📍 core.enhanced_state_saver.EnhancedStateSaver

  __init__(self, provider: str, api_key: Optional[str], model: Optional[str], verbose: bool)
    📍 core.coding_agent.CodingAgent

  __init__(self, user_agent, rate_limit, max_pages, timeout, proxies)
    📍 core.web_agent.WebAgent

  __init__(self, provider, api_key, model, verbose)
    📍 core.agent.CryptoAgent

  __init__(self)
    📍 core.user_interaction.UserInteractionHandler
    💡 Initialize the user interaction handler.

  __init__(self, tools_dir: Union[str, Path]) -> None
    📍 core.code_agent.DynamicToolRegistry

  __init__(self, allowed_modules: Optional[List[str]], max_execution_time: int, memory_limit: int) -> None
    📍 core.code_agent.SafeExecutionEnvironment

  __init__(self, llm_agent: Optional[Any], tools_dir: Union[str, Path], max_execution_time: int, memory_limit: int) -> None
    📍 core.code_agent.CodeAgent

  __init__(self)
    📍 core.binwalk_wrapper.Module

  __init__(self)
    📍 core.binwalk_wrapper.Signature

  __init__(self)
    📍 core.binwalk_wrapper.Extraction

  __init__(self)
    📍 core.binwalk_wrapper.Modules

  __init__(self, verbose: bool)
    📍 core.logger.SolutionLogger

  __init__(self, provider, api_key, model)
    📍 core.vision_agent.VisionAgent

  __post_init__(self)
    📍 core.state.State

  __str__(self) -> str
    📍 core.state.State
    💡 String representation of the state

  _analyze_combined_files(self, state: State) -> State
    📍 core.coding_agent.CodingAgent

  _analyze_file(self, state: State, filename: str) -> State
    📍 core.coding_agent.CodingAgent

  _analyze_with_anthropic(self, image: Image.Image, max_image_size: int) -> Dict[str, Any]
    📍 core.vision_agent.VisionAgent

  _analyze_with_openai(self, image: Image.Image, max_image_size: int) -> Dict[str, Any]
    📍 core.vision_agent.VisionAgent

  _assess_state(self, state: State) -> str
    📍 core.agent.CryptoAgent

  _attempt_direct_solution(self, state: State) -> State
    📍 core.coding_agent.CodingAgent

  _attempt_direct_solution(self, state: State) -> None
    📍 core.agent.CryptoAgent

  _calculate_analysis_duration(self, state) -> Optional[str]
    📍 core.enhanced_state_saver.EnhancedStateSaver
    💡 Calculate analysis duration from timestamps

  _check_for_arweave_patterns(self, state: Any) -> bool
    📍 core.code_agent.CodeAgent

  _count_high_confidence_extractions(self, state) -> int
    📍 core.enhanced_state_saver.EnhancedStateSaver
    💡 Count high-confidence steganographic extractions

  _create_arweave_tools(self, state: Any) -> List[str]
    📍 core.code_agent.CodeAgent

  _create_compressed_archive(self, saved_files: Dict[str, str], base_name: str) -> Optional[str]
    📍 core.enhanced_state_saver.EnhancedStateSaver
    💡 Create a compressed archive of all generated files

  _create_default_tools(self) -> List[str]
    📍 core.code_agent.CodeAgent
    💡 Create a set of default tools for cryptographic puzzles.

  _create_direct_solution_chain(self)
    📍 core.agent.CryptoAgent
    💡 Create the chain for attempting direct solutions.

  _create_main_results(self, state, puzzle_path: str) -> Dict[str, Any]
    📍 core.enhanced_state_saver.EnhancedStateSaver
    💡 Create the main results dictionary with comprehensive data

  _create_safe_globals(self) -> Dict[str, Any]
    📍 core.code_agent.SafeExecutionEnvironment
    💡 Create a safe globals dictionary.

  _create_state_assessment_chain(self)
    📍 core.agent.CryptoAgent
    💡 Create the chain for assessing the puzzle state.

  _create_strategy_chain(self)
    📍 core.agent.CryptoAgent
    💡 Create the chain for selecting analysis strategies.

  _create_summary_file(self, state, puzzle_path: str, saved_files: Dict[str, str], summary_path: Path)
    📍 core.enhanced_state_saver.EnhancedStateSaver
    💡 Create a summary file with key information and file locations

  _extract_key_insights(self, state) -> Dict[str, List[str]]
    📍 core.enhanced_state_saver.EnhancedStateSaver
    💡 Extract and categorize key insights

  _fallback_assessment(self, state)
    📍 core.agent.CryptoAgent

  _fallback_direct_solution(self, state)
    📍 core.agent.CryptoAgent

  _fallback_strategy(self, state)
    📍 core.agent.CryptoAgent

  _find_bitcoin_addresses(self, text: str, transform: Dict[str, Any]) -> List[Dict[str, str]]
    📍 core.enhanced_state_saver.EnhancedStateSaver
    💡 Find Bitcoin addresses

  _find_ethereum_addresses(self, text: str, transform: Dict[str, Any]) -> List[Dict[str, str]]
    📍 core.enhanced_state_saver.EnhancedStateSaver
    💡 Find Ethereum addresses

  _find_hex_keys(self, text: str, transform: Dict[str, Any]) -> List[Dict[str, str]]
    📍 core.enhanced_state_saver.EnhancedStateSaver
    💡 Find hex strings that could be cryptographic keys

  _find_hex_patterns(self, text: str, length: int) -> List[str]
    📍 core.enhanced_state_saver.EnhancedStateSaver
    💡 Find hex patterns of specific length

  _find_mnemonic_phrases(self, text: str, transform: Dict[str, Any]) -> List[Dict[str, str]]
    📍 core.enhanced_state_saver.EnhancedStateSaver
    💡 Find potential BIP39 mnemonic phrases

  _find_wif_keys(self, text: str, transform: Dict[str, Any]) -> List[Dict[str, str]]
    📍 core.enhanced_state_saver.EnhancedStateSaver
    💡 Find WIF format private keys

  _generate_fallback_code(self, task_description: str, required_outputs: Optional[List[str]]) -> str
    📍 core.code_agent.CodeAgent

  _generate_html_report(self, state, puzzle_path: str) -> str
    📍 core.enhanced_state_saver.EnhancedStateSaver
    💡 Generate HTML report content

  _get_puzzle_name(self, puzzle_path: str) -> str
    📍 core.enhanced_state_saver.EnhancedStateSaver
    💡 Extract a clean puzzle name from the path

  _handle_help_command(self) -> Dict[str, Any]
    📍 core.user_interaction.UserInteractionHandler
    💡 Handle the help command.

  _handle_realtime_finding(self, finding_type: str, analyzer: str, content: str) -> None
    📍 core.agent.CryptoAgent

  _handle_status_command(self) -> Dict[str, Any]
    📍 core.user_interaction.UserInteractionHandler
    💡 Handle the status command.

  _indent_code(self, code: str, spaces: int) -> str
    📍 core.code_agent.SafeExecutionEnvironment

  _infer_puzzle_type(self) -> None
    📍 core.state.State
    💡 Try to infer the puzzle type from available data

  _initialize_client(self)
    📍 core.vision_agent.VisionAgent

  _initialize_llm(self)
    📍 core.agent.CryptoAgent

  _initialize_llm_agent(self) -> Optional[CryptoAgent]
    📍 core.coding_agent.CodingAgent

  _input_listener(self)
    📍 core.user_interaction.UserInteractionHandler
    💡 Thread function that listens for user input.

  _is_likely_text(self, data: bytes) -> bool
    📍 core.state.State
    💡 Check if binary data is likely to be text

  _is_potential_mnemonic(self, phrase: str) -> bool
    📍 core.enhanced_state_saver.EnhancedStateSaver
    💡 Basic check if a phrase could be a BIP39 mnemonic

  _is_text_file(self, filename: str, content: bytes) -> bool
    📍 core.coding_agent.CodingAgent

  _load_existing_tools(self) -> None
    📍 core.code_agent.DynamicToolRegistry
    💡 Load existing tools from the tools directory.

  _load_file(self)
    📍 core.state.State
    💡 Load puzzle_file into binary_data or puzzle_text based on type.

  _make_safe_filename(self, name: str) -> str
    📍 core.enhanced_state_saver.EnhancedStateSaver
    💡 Make a string safe for use as a filename

  _resize_image_if_needed(self, image: Image.Image, max_size: int) -> Image.Image
    📍 core.vision_agent.VisionAgent

  _review_analyzer_results(self, state: State, analyzer_name: str, previous_insights_count: int, previous_transformations_count: int) -> Dict
    📍 core.agent.CryptoAgent

  _run_fallback_analysis(self, state: State) -> State
    📍 core.coding_agent.CodingAgent

  _safe_write_json(self, filepath: Path, data: Dict[str, Any])
    📍 core.enhanced_state_saver.EnhancedStateSaver
    💡 Safely write JSON data with error handling

  _sanitize_transformation(self, transformation: Dict[str, Any]) -> Dict[str, Any]
    📍 core.enhanced_state_saver.EnhancedStateSaver
    💡 Sanitize transformation data for JSON serialization

  _save_analysis_report(self, state, puzzle_path: str, report_path: Path)
    📍 core.enhanced_state_saver.EnhancedStateSaver
    💡 Save a detailed analysis report in Markdown format

  _save_binary_data(self, state, base_name: str) -> Dict[str, str]
    📍 core.enhanced_state_saver.EnhancedStateSaver
    💡 Save binary data extractions

  _save_execution_log(self, state, log_path: Path)
    📍 core.enhanced_state_saver.EnhancedStateSaver
    💡 Save execution log with all insights in chronological order

  _save_html_report(self, state, puzzle_path: str, report_path: Path)
    📍 core.enhanced_state_saver.EnhancedStateSaver
    💡 Save a comprehensive HTML report

  _save_potential_keys(self, state, base_name: str) -> Dict[str, str]
    📍 core.enhanced_state_saver.EnhancedStateSaver
    💡 Save potential cryptographic keys found in the analysis

  _save_steganography_data(self, state, base_name: str) -> Dict[str, str]
    📍 core.enhanced_state_saver.EnhancedStateSaver
    💡 Save extracted steganographic data to separate files

  _save_transformations(self, state, base_name: str) -> Dict[str, str]
    📍 core.enhanced_state_saver.EnhancedStateSaver
    💡 Save all transformations as individual files

  _select_strategy(self, state: State, assessment: str, previous_results: str) -> Dict
    📍 core.agent.CryptoAgent

  _send_realtime_findings_to_llm(self) -> None
    📍 core.agent.CryptoAgent

  _send_to_llm(self, prompt)
    📍 core.agent.CryptoAgent

  _send_to_llm_without_response(self, prompt: str) -> None
    📍 core.agent.CryptoAgent

  _setup_directories(self)
    📍 core.enhanced_state_saver.EnhancedStateSaver
    💡 Set up all necessary directories

  _should_promote_to_puzzle_text(self, name: str, output_data: Any) -> bool
    📍 core.state.State
    💡 Determine if transformation output should be promoted to puzzle_text

  _should_try_llm_initialization(self) -> bool
    📍 core.coding_agent.CodingAgent

  _should_try_llm_initialization(self) -> bool
    📍 core.agent.CryptoAgent

  _template_base64_tool(self, required_outputs: Optional[List[str]]) -> str
    📍 core.code_agent.CodeAgent
    💡 Create a template for base64 encoding/decoding.

  _template_caesar_tool(self, required_outputs: Optional[List[str]]) -> str
    📍 core.code_agent.CodeAgent
    💡 Create a template for Caesar cipher.

  _template_frequency_analysis_tool(self, required_outputs: Optional[List[str]]) -> str
    📍 core.code_agent.CodeAgent
    💡 Create a template for frequency analysis.

  _template_generic_analysis_tool(self, required_outputs: Optional[List[str]]) -> str
    📍 core.code_agent.CodeAgent
    💡 Create a template for generic text analysis.

  _template_hash_tool(self, required_outputs: Optional[List[str]]) -> str
    📍 core.code_agent.CodeAgent
    💡 Create a template for hash functions.

  _template_xor_tool(self, required_outputs: Optional[List[str]]) -> str
    📍 core.code_agent.CodeAgent
    💡 Create a template for XOR cipher.

  _test_api_access(self)
    📍 core.agent.CryptoAgent
    💡 Test if the API key is valid.

  _try_decode_string(self, data_str: str) -> Optional[bytes]
    📍 core.enhanced_state_saver.EnhancedStateSaver
    💡 Try to decode a string as hex, base64, or other formats

  _verify_solution(self, state: State, solution: str) -> bool
    📍 core.coding_agent.CodingAgent

  add_clue(self, text: str, source: str) -> None
    📍 core.state.State
    💡 Add a clue with source information

  add_insight(self, text: str, analyzer: str) -> None
    📍 core.state.State
    💡 Add an insight with proper formatting

  add_pattern(self, text: str, source: str, category: str) -> None
    📍 core.state.State
    💡 Add a pattern from similar puzzles

  add_related_file(self, filename: str, content: bytes) -> None
    📍 core.state.State
    💡 Add a related file with metadata

  add_transformation(self, name: str, description: str, input_data: Any, output_data: Any, analyzer: str) -> None
    📍 core.state.State
    💡 Add a transformation with enhanced handling of extracted text

  algebra_solver(equations: List[str], variables: List[str]) -> Dict[str, Any]
    📍 core.arweave_tools

  analyze(self, state: State, max_iterations: int) -> State
    📍 core.coding_agent.CodingAgent

  analyze(self, state: State, max_iterations: int) -> State
    📍 core.agent.CryptoAgent

  analyze_and_create_tools(self, state: Any) -> List[str]
    📍 core.code_agent.CodeAgent

  analyze_audio_spectrogram(data: bytes) -> Dict[str, Any]
    📍 core.steganography_tools

  analyze_cryptographic_information(self, query: str) -> Dict[str, Any]
    📍 core.web_agent.WebAgent

  analyze_image(self, image_data: bytes, max_image_size: int) -> Dict[str, Any]
    📍 core.vision_agent.VisionAgent

  analyze_steganography(file_path, image_data, bit_planes, regions)
    📍 core.steganography_extractor

  analyze_stego(data: bytes, file_type: str) -> Dict[str, Any]
    📍 core.steganography_tools

  analyze_zero_width_chars(text: str) -> Dict[str, Any]
    📍 core.steganography_tools

  arweave_fetch(tx_id: str, gateway: str) -> Dict[str, Any]
    📍 core.arweave_tools_part2

  beep_pattern_finder(start_time: str, interval: int, pattern_description: str, target_count: int) -> Dict[str, Any]
    📍 core.arweave_tools

  browse_puzzles(puzzles_dir)
    📍 core.utils
    💡 Browse the available puzzles in the directory.

  calculate_entropy(data: bytes) -> float
    📍 core.arweave_tools_part2
    💡 Calculate Shannon entropy of data.

  check_binary_pattern(binary_data)
    📍 core.steganography_extractor

  check_for_input(self) -> Optional[str]
    📍 core.user_interaction.UserInteractionHandler

  check_for_user_input() -> Optional[str]
    📍 core.user_interaction

  clear_pending_llm_feedback(self) -> None
    📍 core.logger.SolutionLogger

  combinatorics_calculator(problem_type: str, parameters: Dict[str, Any]) -> Dict[str, Any]
    📍 core.arweave_tools_part3

  coordinate_calculator(lat: float, lon: float, operation: str) -> Dict[str, Any]
    📍 core.arweave_tools

  crawl(self, start_url: str, depth, keywords) -> Dict[str, Any]
    📍 core.web_agent.WebAgent

  execute(self, code: str, inputs: Optional[Dict[str, Any]]) -> Dict[str, Any]
    📍 core.code_agent.SafeExecutionEnvironment

  execute_code(self, code: str, inputs: Dict[str, Any]) -> Dict[str, Any]
    📍 core.coding_agent.CodingAgent

  execute_code(self, code: str, inputs: Optional[Dict[str, Any]]) -> Dict[str, Any]
    📍 core.code_agent.CodeAgent

  extract_appended_data(data: bytes) -> Dict[str, Any]
    📍 core.steganography_tools

  extract_first_letters(text: str) -> Dict[str, Any]
    📍 core.steganography_tools

  extract_image_lsb(data: bytes, bit_plane: int, channels: List[str]) -> Dict[str, Any]
    📍 core.steganography_tools

  extract_lsb(data: bytes, file_type: str) -> Optional[bytes]
    📍 core.arweave_tools_part2
    💡 Extract least significant bits from image data.

  extract_lsb_data(img_array, bit_plane)
    📍 core.steganography_extractor

  extract_metadata(data: bytes, file_type: str) -> Dict[str, Any]
    📍 core.arweave_tools_part2
    💡 Extract metadata from file.

  extract_region(img_array, region_name)
    📍 core.steganography_extractor

  extract_strings(data: bytes, min_length: int) -> List[str]
    📍 core.arweave_tools_part2
    💡 Extract printable strings from binary data.

  extract_text(self, html: str) -> str
    📍 core.web_agent.WebAgent

  fetch_url(self, url: str) -> Optional[str]
    📍 core.web_agent.WebAgent

  file_type_router(data: bytes) -> Dict[str, Any]
    📍 core.arweave_tools_part3

  find_clues(puzzle_path)
    📍 core.utils

  find_embedded_files(data: bytes) -> Dict[str, Any]
    📍 core.steganography_tools

  find_patterns(puzzle_path)
    📍 core.utils

  generate_code(self, task_description: str, state: State) -> str
    📍 core.coding_agent.CodingAgent

  generate_code(self, task_description: str, state: Optional[Any], required_outputs: Optional[List[str]]) -> str
    📍 core.code_agent.CodeAgent

  get_content_sample(self, max_size: int, max_binary_size: int) -> str
    📍 core.state.State
    💡 Get a sample of the puzzle content for analysis

  get_insights(self) -> List[Dict[str, Any]]
    📍 core.logger.SolutionLogger

  get_pending_llm_feedback(self) -> List[Dict[str, Any]]
    📍 core.logger.SolutionLogger

  get_puzzle_info(puzzle_path)
    📍 core.utils
    💡 Get information about a puzzle file.

  get_solution(self) -> Optional[str]
    📍 core.logger.SolutionLogger

  get_summary(self) -> str
    📍 core.state.State
    💡 Get a comprehensive summary of the current state

  get_tool(tool_name)
    📍 core.arweave_tools_main
    💡 Get a tool by name.

  get_tool(self, tool_id: str) -> Optional[Callable]
    📍 core.code_agent.DynamicToolRegistry
    💡 Get a tool by ID.

  get_tools_by_category(category)
    📍 core.arweave_tools_main
    💡 Get all tools in a specific category.

  get_transformations(self) -> List[Dict[str, Any]]
    📍 core.logger.SolutionLogger

  integrate_with_state(self, state, query: str) -> Any
    📍 core.web_agent.WebAgent

  integrate_with_state(self, state: Any, analyze_puzzle: bool) -> Any
    📍 core.code_agent.CodeAgent

  integrate_with_state(self, state, image_data: bytes, max_image_size: int) -> Any
    📍 core.vision_agent.VisionAgent

  is_api_key_set(key_name: str) -> bool
    📍 core.coding_agent

  is_binary(self) -> bool
    📍 core.state.State
    💡 Check if state contains binary data

  is_binary_file(self, file_path) -> bool
    📍 core.state.State
    💡 Check if a file is likely binary

  is_meaningful_data(data: Optional[bytes]) -> bool
    📍 core.arweave_tools_part2
    💡 Check if data appears to be meaningful rather than random.

  is_text(self) -> bool
    📍 core.state.State
    💡 Check if state contains text data

  knowledge_graph_query(query_text: str, domain: str) -> Dict[str, Any]
    📍 core.arweave_tools_part3

  linear_program_solver(objective: List[float], constraints_lhs: List[List[float]], constraints_rhs: List[float], bounds: List[Tuple[float, float]], maximize: bool) -> Dict[str, Any]
    📍 core.arweave_tools_part3

  list_tools()
    📍 core.arweave_tools_main
    💡 List all available tools.

  list_tools(self) -> List[Dict[str, Any]]
    📍 core.code_agent.DynamicToolRegistry
    💡 List all registered tools.

  load_clues(puzzle_path)
    📍 core.utils

  load_patterns(puzzle_path)
    📍 core.utils

  load_state(self, puzzle_path: str) -> Optional['State']
    📍 core.enhanced_state_saver.EnhancedStateSaver

  log_insight(self, text: str, analyzer: str, time_str: Optional[str]) -> None
    📍 core.logger.SolutionLogger

  log_solution(self, solution: str) -> None
    📍 core.logger.SolutionLogger

  log_transformation(self, name: str, description: str, input_data: str, output_data: str, analyzer: str, time_str: Optional[str]) -> None
    📍 core.logger.SolutionLogger

  merge_related_state(self, other_state: 'State') -> None
    📍 core.state.State
    💡 Merge insights and transformations from another state

  process_input(self, user_input: str, context: Dict[str, Any]) -> Dict[str, Any]
    📍 core.user_interaction.UserInteractionHandler

  process_user_input(user_input: str, context: Dict[str, Any]) -> Dict[str, Any]
    📍 core.user_interaction

  register_arweave_tools_with_agent(code_agent)
    📍 core.arweave_tools_main
    💡 Register all Arweave tools with the CodeAgent.

  register_callback(name: str, callback: Callable)
    📍 core.user_interaction

  register_callback(self, name: str, callback: Callable)
    📍 core.user_interaction.UserInteractionHandler

  register_llm_feedback_callback(self, callback: Callable[[str, str, str], None]) -> None
    📍 core.logger.SolutionLogger

  register_new_tool(self, task_description: str, state: Optional[Any]) -> Optional[str]
    📍 core.code_agent.CodeAgent

  register_tool(self, code: str, name: Optional[str], description: str) -> Optional[str]
    📍 core.code_agent.DynamicToolRegistry

  remove_tool(self, tool_id: str) -> bool
    📍 core.code_agent.DynamicToolRegistry
    💡 Remove a tool by ID.

  riddle_lookup(riddle_text: str) -> Dict[str, Any]
    📍 core.arweave_tools

  run_binwalk(data: bytes) -> Dict[str, Any]
    📍 core.steganography_tools

  run_zsteg(data: bytes) -> Dict[str, Any]
    📍 core.steganography_tools

  save_comprehensive_results(self, state, puzzle_path: str, create_compressed: bool) -> Dict[str, str]
    📍 core.enhanced_state_saver.EnhancedStateSaver

  scan(target_file: str, signature: bool, extract: bool, quiet: bool, directory: Optional[str]) -> List[Module]
    📍 core.binwalk_wrapper

  search(self, query: str, search_engine, num_results) -> List[Dict[str, str]]
    📍 core.web_agent.WebAgent

  set_binary_data(self, data: bytes) -> None
    📍 core.state.State
    💡 Store binary data and record insight

  set_context(context: Dict[str, Any])
    📍 core.user_interaction

  set_context(self, context: Dict[str, Any])
    📍 core.user_interaction.UserInteractionHandler

  set_puzzle_file(self, file_path: str) -> None
    📍 core.state.State
    💡 Set the puzzle file and load its content

  set_puzzle_text(self, txt: str) -> None
    📍 core.state.State
    💡 Set puzzle text and log the change

  set_solution(self, sol: str) -> None
    📍 core.state.State
    💡 Record the solution and log it

  setup_logging(verbose)
    📍 core.utils
    💡 Set up logging for the application.

  start_listening(self)
    📍 core.user_interaction.UserInteractionHandler
    💡 Start listening for user input in a separate thread.

  start_user_interaction()
    📍 core.user_interaction
    💡 Start the user interaction handler.

  steganalysis(data: bytes, method: str) -> Dict[str, Any]
    📍 core.arweave_tools_part2

  stop_listening(self)
    📍 core.user_interaction.UserInteractionHandler
    💡 Stop listening for user input.

  stop_user_interaction()
    📍 core.user_interaction
    💡 Stop the user interaction handler.

  timeline_analyzer(events: List[Dict[str, str]], query: str) -> Dict[str, Any]
    📍 core.arweave_tools_part3

  to_dict(self) -> Dict[str, Any]
    📍 core.state.State
    💡 Convert state to dictionary for serialization

  use_tool(self, tool_id: str, inputs: Optional[Dict[str, Any]]) -> Dict[str, Any]
    📍 core.code_agent.CodeAgent

🔧 OTHER
--------------------------------------------------

  __init__(self, root_path: str, exclude_dirs: List[str], exclude_files: List[str])
    📍 project_walker.ProjectWalker

  __init__(self, agent: CryptoAgent)
    📍 ui.interactive.InteractiveSession

  __post_init__(self)
    📍 project_walker.FunctionInfo

  __post_init__(self)
    📍 project_walker.ClassInfo

  _show_results(self)
    📍 ui.interactive.InteractiveSession
    💡 Show brief analysis results

  analyze_file(self, file_path: Path) -> Optional[ModuleInfo]
    📍 project_walker.ProjectWalker
    💡 Analyze a single Python file.

  browse_puzzle_collection(puzzles_dir, agent, results_dir, use_clues, verbose)
    📍 main
    💡 Browse the puzzle collection interactively.

  configure_api_keys()
    📍 install
    💡 Configure API keys for the project.

  create_collaboration_summary(project_info, full_summary)
    📍 quick_analyze
    💡 Create a concise summary perfect for collaboration.

  create_function_index(self, project_info: Dict[str, List[ModuleInfo]]) -> str
    📍 project_walker.ProjectWalker
    💡 Create a searchable index of all functions and their purposes.

  create_test_png()
    📍 test
    💡 Create a minimal test PNG for testing

  create_virtual_environment(venv_path: str) -> bool
    📍 install

  display_analyzer_help()
    📍 ui.cli
    💡 Display help information about available analyzers.

  display_banner()
    📍 ui.cli
    💡 Display the Crypto Hunter banner.

  display_progress(current: int, total: int, message: str)
    📍 ui.cli

  display_results(state, puzzle_path)
    📍 main
    💡 Display the analysis results in a structured format.

  display_results(state: State)
    📍 ui.cli

  display_welcome()
    📍 main
    💡 Display the welcome message.

  do_analyze(self, line)
    📍 ui.interactive.InteractiveSession
    💡 Run analysis: analyze [analyzer_name] [iterations]

  do_analyzers(self, line)
    📍 ui.interactive.InteractiveSession
    💡 List available analyzers

  do_exit(self, line)
    📍 ui.interactive.InteractiveSession
    💡 Exit the interactive session

  do_insights(self, line)
    📍 ui.interactive.InteractiveSession
    💡 Show all insights: insights [count]

  do_load(self, line)
    📍 ui.interactive.InteractiveSession
    💡 Load a puzzle file: load <filepath>

  do_quit(self, line)
    📍 ui.interactive.InteractiveSession
    💡 Exit the interactive session

  do_reset(self, line)
    📍 ui.interactive.InteractiveSession
    💡 Reset the current session

  do_solution(self, line)
    📍 ui.interactive.InteractiveSession
    💡 Show solution if found

  do_status(self, line)
    📍 ui.interactive.InteractiveSession
    💡 Show current puzzle status

  do_transformations(self, line)
    📍 ui.interactive.InteractiveSession
    💡 Show transformations: transformations [count]

  emptyline(self)
    📍 ui.interactive.InteractiveSession
    💡 Override to do nothing on empty line

  extract_constants(self, tree: ast.AST) -> List[str]
    📍 project_walker.ProjectWalker
    💡 Extract module-level constants (uppercase variables).

  extract_decorators(self, node) -> List[str]
    📍 project_walker.ProjectWalker
    💡 Extract decorator names.

  extract_docstring(self, node) -> Optional[str]
    📍 project_walker.ProjectWalker
    💡 Extract docstring from a node.

  extract_imports(self, tree: ast.AST) -> List[str]
    📍 project_walker.ProjectWalker
    💡 Extract import statements.

  extract_signature(self, node: ast.FunctionDef) -> str
    📍 project_walker.ProjectWalker
    💡 Extract function signature as string.

  generate_summary(self, project_info: Dict[str, List[ModuleInfo]]) -> str
    📍 project_walker.ProjectWalker
    💡 Generate a human-readable summary.

  get_venv_pip(venv_path: str) -> str
    📍 install

  get_venv_python(venv_path: str) -> str
    📍 install

  install_dependencies(venv_path: str, dev: bool) -> bool
    📍 install

  interactive_menu()
    📍 main
    💡 Display the interactive menu.

  interactive_mode(agent)
    📍 main
    💡 Run in interactive mode.

  main()
    📍 test
    💡 Run all tests

  main()
    📍 test_lsb_extraction

  main()
    📍 install
    💡 Main entry point.

  main()
    📍 project_walker

  main()
    📍 main
    💡 Main entry point for the application.

  parse_arguments()
    📍 install
    💡 Parse command line arguments.

  parse_arguments()
    📍 main
    💡 Parse command-line arguments.

  print_error(message: str)
    📍 ui.cli

  print_state_details(state)
    📍 main
    💡 Print detailed insights and transformations from the state.

  print_success(message: str)
    📍 ui.cli

  print_warning(message: str)
    📍 ui.cli

  process_all_files_in_folder(folder_path, agent, output_dir, iterations, results_dir, use_clues, verbose)
    📍 main

  process_puzzle(puzzle_path, agent, output_dir, iterations, results_dir, use_clues, verbose)
    📍 main

  quick_analyze()
    📍 quick_analyze
    💡 Run a quick analysis and generate all useful output files.

  read_last_results(results_dir)
    📍 main

  run_command(command: List[str], cwd: Optional[str]) -> bool
    📍 install

  save_detailed_json(self, project_info: Dict[str, List[ModuleInfo]], output_file: str)
    📍 project_walker.ProjectWalker
    💡 Save detailed project information as JSON.

  save_results_to_file(state: State, file_path: str)
    📍 ui.cli

  select_provider_interactively()
    📍 main
    💡 Allow user to select an LLM provider.

  setup_environment(args)
    📍 main
    💡 Set up the environment for the application.

  setup_logging(verbose: bool)
    📍 ui.cli

  setup_project_structure()
    📍 install
    💡 Ensure the project structure is set up correctly.

  start_interactive_session(agent: CryptoAgent)
    📍 ui.interactive
    💡 Start an interactive session

  test_analyzer_registration()
    📍 test
    💡 Test that analyzers are properly registered

  test_dependencies()
    📍 test
    💡 Test that required dependencies are available

  test_enhanced_image_analyzer()
    📍 test
    💡 Test the enhanced image analyzer

  test_enhanced_state()
    📍 test
    💡 Test the enhanced state management

  test_safe_execution()
    📍 test_code_agent
    💡 Test the SafeExecutionEnvironment with a simple code snippet.

  walk_project(self) -> Dict[str, List[ModuleInfo]]
    📍 project_walker.ProjectWalker
    💡 Walk the entire project and extract information.

🔧 TOOLS
--------------------------------------------------

  display_results(results: Dict[str, Any])
    📍 tools.benchmark

  get_puzzle_files(directory: str) -> List[str]
    📍 tools.benchmark

  load_result(file_path: str) -> Dict[str, Any]
    📍 tools.visualize_results

  main()
    📍 tools.benchmark
    💡 Main entry point.

  main()
    📍 tools.visualize_results
    💡 Main entry point.

  parse_arguments()
    📍 tools.benchmark
    💡 Parse command line arguments.

  parse_arguments()
    📍 tools.visualize_results
    💡 Parse command line arguments.

  plot_results(results: Dict[str, Any], output_path: Optional[str])
    📍 tools.benchmark

  run_benchmark(analyzers: Dict[str, Any], puzzle_files: List[str], iterations: int) -> Dict[str, Any]
    📍 tools.benchmark

  save_results(results: Dict[str, Any], file_path: str)
    📍 tools.benchmark

  test_arweave_tools_registration()
    📍 test_arweave_tools
    💡 Test that Arweave tools are registered correctly.

  visualize_as_graph(result: Dict[str, Any], output_path: Optional[str])
    📍 tools.visualize_results

  visualize_as_table(result: Dict[str, Any])
    📍 tools.visualize_results

  visualize_as_timeline(result: Dict[str, Any], output_path: Optional[str])
    📍 tools.visualize_results