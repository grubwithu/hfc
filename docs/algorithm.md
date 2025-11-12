// ============================================
// 模块一：约束识别与聚类模块
// ============================================

// 1.1 重要约束结构
STRUCT ImportantConstraint:
    branch_id: str
    function_name: str
    source_file: str
    line_number: int
    importance_score: float
    hit_count: int
    complexity: int
    reachability_depth: int
    uncovered_complexity: int

// 1.2 约束组结构
STRUCT ConstraintGroup:
    group_id: str
    main_function: str
    constraints: List[ImportantConstraint]
    total_importance: float

// 1.3 快速识别重要约束
FUNCTION IdentifyImportantConstraints(
    merged_profile: MergedProjectProfile,
    coverage_profile: CoverageProfile
) -> List[ImportantConstraint]:
    
    constraints = []
    
    // 只遍历未覆盖的分支（性能优化）
    uncovered_branches = GetUncoveredBranches(merged_profile, coverage_profile)
    
    FOR EACH branch IN uncovered_branches:
        
        // 获取基础信息
        hit_count = coverage_profile.get_branch_hit_count(branch)  // 通常为0
        complexity = branch.cyclomatic_complexity
        
        // 计算重要性分数（简化公式）
        hit_frequency_weight = 1.0 / (1.0 + hit_count)
        complexity_weight = MIN(complexity / MAX_COMPLEXITY, 1.0)
        
        // 计算未覆盖复杂度
        uncovered_complexity = CalculateUncoveredComplexity(branch, merged_profile)
        uncovered_weight = MIN(uncovered_complexity / MAX_UNCOVERED, 1.0)
        
        // 计算可达性深度
        reachability_depth = CalculateReachabilityDepth(branch, merged_profile)
        depth_weight = 1.0 / (1.0 + reachability_depth)
        
        // 综合重要性分数
        importance_score = (
            ALPHA * hit_frequency_weight +
            BETA * complexity_weight +
            GAMMA * uncovered_weight +
            DELTA * depth_weight
        )
        
        // 只保留超过阈值的约束
        IF importance_score > IMPORTANCE_THRESHOLD:
            constraint = ImportantConstraint(
                branch_id = branch.id,
                function_name = branch.function_name,
                source_file = branch.source_file,
                line_number = branch.line_number,
                importance_score = importance_score,
                hit_count = hit_count,
                complexity = complexity,
                reachability_depth = reachability_depth,
                uncovered_complexity = uncovered_complexity
            )
            constraints.append(constraint)
    
    // 按重要性排序，只保留Top-K（性能优化）
    SORT(constraints, key=importance_score, order=DESCENDING)
    RETURN constraints[:MAX_CONSTRAINTS]

// 1.4 计算未覆盖复杂度（递归，但限制深度）
FUNCTION CalculateUncoveredComplexity(
    branch: BranchProfile,
    merged_profile: MergedProjectProfile,
    max_depth: int = 3
) -> int:
    
    IF max_depth <= 0:
        RETURN 0
    
    IF branch.is_covered:
        RETURN 0
    
    uncovered_complexity = branch.cyclomatic_complexity
    
    // 只计算直接子分支（避免深度递归）
    child_branches = GetDirectChildBranches(branch, merged_profile)
    FOR EACH child_branch IN child_branches:
        uncovered_complexity += CalculateUncoveredComplexity(
            child_branch, merged_profile, max_depth - 1
        )
    
    RETURN uncovered_complexity

// 1.5 计算可达性深度（BFS，O(V+E)）
FUNCTION CalculateReachabilityDepth(
    branch: BranchProfile,
    merged_profile: MergedProjectProfile
) -> int:
    
    target_function = branch.function_name
    min_depth = INFINITY
    
    // 从所有fuzzer入口点计算最短路径
    FOR EACH fuzzer_profile IN merged_profile.profiles:
        entry_point = fuzzer_profile.entry_point
        
        depth = FindShortestPathDepth(
            entry_point,
            target_function,
            merged_profile.calltree
        )
        
        min_depth = MIN(min_depth, depth)
    
    RETURN min_depth IF min_depth < INFINITY ELSE MAX_DEPTH

// 1.6 快速约束分组（基于函数归属，避免复杂聚类）
FUNCTION GroupConstraintsByFunction(
    constraints: List[ImportantConstraint],
    merged_profile: MergedProjectProfile
) -> List[ConstraintGroup]:
    
    // 第一步：按函数分组
    function_groups = {}  // function_name -> ConstraintGroup
    
    FOR EACH constraint IN constraints:
        func_name = constraint.function_name
        
        IF func_name NOT IN function_groups:
            function_groups[func_name] = ConstraintGroup(
                group_id = GenerateGroupId(),
                main_function = func_name,
                constraints = [],
                total_importance = 0.0
            )
        
        function_groups[func_name].constraints.append(constraint)
        function_groups[func_name].total_importance += constraint.importance_score
    
    // 第二步：合并小函数组到相关大函数组（基于调用关系）
    merged_groups = MergeRelatedFunctionGroups(function_groups, merged_profile)
    
    RETURN merged_groups.values()

// 1.7 合并相关函数组（基于调用树，O(n)复杂度）
FUNCTION MergeRelatedFunctionGroups(
    function_groups: Dict[str, ConstraintGroup],
    merged_profile: MergedProjectProfile
) -> Dict[str, ConstraintGroup]:
    
    // 如果函数A直接调用函数B，且B的约束数少，合并到A
    groups_to_remove = []
    
    FOR EACH (func_a, group_a) IN function_groups.items():
        // 获取函数A的直接被调用者
        callees = GetDirectCallees(func_a, merged_profile)
        
        FOR EACH func_b IN callees:
            IF func_b IN function_groups:
                group_b = function_groups[func_b]
                
                // 如果B组小且A组大，合并B到A
                IF len(group_b.constraints) < MERGE_THRESHOLD AND \
                   len(group_a.constraints) >= MERGE_THRESHOLD:
                    
                    group_a.constraints.extend(group_b.constraints)
                    group_a.total_importance += group_b.total_importance
                    groups_to_remove.append(func_b)
    
    // 移除已合并的组
    FOR EACH func IN groups_to_remove:
        DELETE function_groups[func]
    
    RETURN function_groups

// 1.8 实时更新约束组（周期性调用）
FUNCTION UpdateConstraintGroups(
    existing_groups: List[ConstraintGroup],
    merged_profile: MergedProjectProfile,
    coverage_data: CoverageProfile
) -> List[ConstraintGroup]:
    
    // 重新识别重要约束
    new_constraints = IdentifyImportantConstraints(
        merged_profile, coverage_data
    )
    
    // 更新现有组：移除已覆盖的约束
    updated_groups = []
    FOR EACH group IN existing_groups:
        remaining_constraints = []
        FOR EACH constraint IN group.constraints:
            branch = GetBranchById(constraint.branch_id, merged_profile)
            IF NOT coverage_data.is_branch_covered(branch):
                remaining_constraints.append(constraint)
        
        IF len(remaining_constraints) > 0:
            group.constraints = remaining_constraints
            group.total_importance = SUM(c.importance_score FOR c IN remaining_constraints)
            updated_groups.append(group)
    
    // 为新约束创建新组
    IF len(new_constraints) > 0:
        new_groups = GroupConstraintsByFunction(new_constraints, merged_profile)
        updated_groups.extend(new_groups)
    
    RETURN updated_groups



// ============================================
// 模块二：约束-模糊器匹配模块
// ============================================

// 2.1 预定义的约束类型枚举
ENUM ConstraintType:
    // 字符串匹配类
    SHORT_STRING_MATCH,        // 短字符串匹配（1-10字节）
    MEDIUM_STRING_MATCH,       // 中等字符串匹配（11-50字节）
    LONG_STRING_MATCH,         // 长字符串匹配（>50字节）
    PREFIX_STRING_MATCH,       // 前缀匹配
    SUFFIX_STRING_MATCH,       // 后缀匹配
    KEYWORD_MATCH,             // 关键词匹配
    CASE_SENSITIVE_MATCH,      // 大小写敏感匹配
    CASE_INSENSITIVE_MATCH,    // 大小写不敏感匹配
    
    // 数值范围类
    SMALL_NUMERIC_RANGE,       // 小数值范围（0-100）
    MEDIUM_NUMERIC_RANGE,      // 中等数值范围（100-10000）
    LARGE_NUMERIC_RANGE,       // 大数值范围（>10000）
    SIGNED_INTEGER_CHECK,      // 有符号整数检查
    UNSIGNED_INTEGER_CHECK,    // 无符号整数检查
    FLOATING_POINT_RANGE,      // 浮点数范围
    BOUNDARY_VALUE_CHECK,      // 边界值检查
    MODULO_CHECK,              // 模运算检查
    
    // 算术约束类
    LINEAR_ARITHMETIC,         // 线性算术
    NONLINEAR_ARITHMETIC,      // 非线性算术
    MULTIPLICATIVE_RELATION,   // 乘法关系
    ADDITIVE_RELATION,         // 加法关系
    COMPARISON_CHAIN,          // 比较链
    BITWISE_OPERATION,         // 位运算
    
    // 长度约束类
    FIXED_LENGTH_CHECK,        // 固定长度检查
    MIN_LENGTH_CHECK,          // 最小长度检查
    MAX_LENGTH_CHECK,          // 最大长度检查
    LENGTH_RANGE_CHECK,        // 长度范围检查
    MULTIPLE_LENGTH_CHECK,     // 多个长度检查
    
    // 格式约束类
    JSON_FORMAT,               // JSON格式验证
    XML_FORMAT,                // XML格式验证
    URL_FORMAT,                // URL格式验证
    EMAIL_FORMAT,              // Email格式验证
    REGEX_PATTERN,             // 正则表达式匹配
    BASE64_ENCODING,           // Base64编码格式
    HEX_ENCODING,              // 十六进制编码格式
    UTF8_VALIDATION,           // UTF-8编码验证
    ASCII_ONLY,                // ASCII字符检查
    
    // 哈希/校验类
    MD5_HASH_CHECK,            // MD5哈希校验
    SHA1_HASH_CHECK,           // SHA1哈希校验
    SHA256_HASH_CHECK,         // SHA256哈希校验
    CRC_CHECKSUM,              // CRC校验和
    SIMPLE_CHECKSUM,           // 简单校验和
    PARITY_CHECK,              // 奇偶校验
    
    // 加密相关类
    ENCRYPTION_KEY_CHECK,      // 加密密钥检查
    IV_CHECK,                  // 初始化向量检查
    SIGNATURE_VERIFICATION,    // 数字签名验证
    CERTIFICATE_VALIDATION,    // 证书验证
    
    // 时间相关类
    TIMESTAMP_CHECK,           // 时间戳检查
    DATE_VALIDATION,           // 日期验证
    TIME_RANGE_CHECK,          // 时间范围检查
    SEQUENCE_NUMBER,           // 序列号检查
    
    // 状态依赖类
    STATE_MACHINE_TRANSITION,  // 状态机转换
    SESSION_VALIDATION,        // 会话验证
    AUTHENTICATION_CHECK,      // 认证检查
    AUTHORIZATION_CHECK,       // 授权检查
    LOCK_STATUS_CHECK,         // 锁状态检查
    INITIALIZATION_CHECK,      // 初始化检查
    
    // 路径/深度类
    SHALLOW_PATH,              // 浅路径（调用深度1-3）
    MEDIUM_PATH,               // 中等路径（调用深度4-7）
    DEEP_PATH,                 // 深路径（调用深度>7）
    COMPLEX_CALL_CHAIN,        // 复杂调用链
    
    // 数据结构类
    ARRAY_BOUNDS_CHECK,        // 数组边界检查
    STRUCTURE_VALIDATION,      // 结构体验证
    POINTER_NULL_CHECK,        // 指针空值检查
    POINTER_VALIDITY_CHECK,    // 指针有效性检查
    MEMORY_ALIGNMENT,          // 内存对齐检查
    
    // 网络协议类
    HTTP_METHOD_CHECK,         // HTTP方法检查
    HTTP_HEADER_VALIDATION,    // HTTP头验证
    PROTOCOL_VERSION_CHECK,    // 协议版本检查
    PORT_NUMBER_CHECK,         // 端口号检查
    IP_ADDRESS_VALIDATION,     // IP地址验证
    
    // 文件系统类
    FILE_EXTENSION_CHECK,      // 文件扩展名检查
    PATH_TRAVERSAL_CHECK,      // 路径遍历检查
    FILE_SIZE_LIMIT,           // 文件大小限制
    PERMISSION_CHECK,          // 权限检查
    
    // 通用类
    GENERAL_CONSTRAINT,        // 一般约束
    MULTIPLE_CONSTRAINT,       // 多重约束
    UNKNOWN_CONSTRAINT         // 未知约束

// 2.2 约束实例结构
STRUCT ConstraintInstance:
    constraint_type: ConstraintType
    code_example: str
    pattern_signature: str
    detection_rules: List[Rule]

// 2.3 约束实例库（预定义）
CONSTRAINT_INSTANCES = {
    ConstraintType.SHORT_STRING_MATCH: [
        ConstraintInstance(
            type = SHORT_STRING_MATCH,
            code_example = "if (strcmp(input, \"PASS\") == 0)",
            pattern_signature = "strcmp(*, \"literal\") == 0",
            detection_rules = [
                Rule(function_name_contains=["strcmp", "strncmp"]),
                Rule(has_string_literal=True),
                Rule(literal_length <= 10)
            ]
        )
    ],
    ConstraintType.MODULO_CHECK: [
        ConstraintInstance(
            code_example = "if (len % 4 == 0)",
            pattern_signature = "var % constant == 0"
        )
    ],
    // ... 其他约束类型的实例
}

// 2.4 约束特征结构
STRUCT ConstraintFeatures:
    has_string_comparison: bool
    string_length_range: (int, int)
    is_case_sensitive: bool
    has_numeric_comparison: bool
    numeric_range: (float, float)
    has_arithmetic_operation: bool
    arithmetic_complexity: int
    has_length_check: bool
    length_check_type: str
    format_type: str
    has_hash_check: bool
    hash_type: str
    has_modulo: bool
    call_depth: int

// 2.5 从分支中提取实际约束特征
FUNCTION ExtractConstraintFeatures(
    branch: BranchProfile,
    debug_info: DebugInfo,
    merged_profile: MergedProjectProfile
) -> ConstraintFeatures:
    
    features = CreateConstraintFeatures()
    condition = GetBranchCondition(branch, debug_info)
    
    // 字符串比较检测
    IF ContainsFunctionCall(condition, ["strcmp", "strncmp", "strcasecmp", "memcmp"]):
        features.has_string_comparison = True
        string_literal = ExtractStringLiteral(condition, debug_info)
        IF string_literal:
            length = len(string_literal)
            features.string_length_range = (length, length)
            features.is_case_sensitive = IsCaseSensitive(condition)
    
    // 数值比较检测
    IF ContainsComparison(condition, [">", "<", ">=", "<=", "==", "!="]):
        features.has_numeric_comparison = True
        numeric_range = ExtractNumericRange(condition, debug_info)
        IF numeric_range:
            features.numeric_range = numeric_range
    
    // 长度检查
    IF ContainsFunctionCall(condition, ["strlen", "length", "size"]):
        features.has_length_check = True
        features.length_check_type = DetermineLengthCheckType(condition)
    
    // 算术运算
    IF ContainsOperator(condition, ["+", "-", "*", "/", "%"]):
        features.has_arithmetic_operation = True
        features.arithmetic_complexity = EstimateArithmeticComplexity(condition)
        IF "%" IN condition:
            features.has_modulo = True
    
    // 格式检测
    format_funcs = {"json_parse": "json", "xml_parse": "xml", "url_parse": "url"}
    FOR EACH (func, format) IN format_funcs.items():
        IF ContainsFunctionCall(condition, [func]):
            features.format_type = format
            BREAK
    
    // 哈希检测
    hash_funcs = ["MD5", "SHA1", "SHA256", "crc32"]
    FOR EACH hash_func IN hash_funcs:
        IF ContainsFunctionCall(condition, [hash_func]):
            features.has_hash_check = True
            features.hash_type = hash_func.lower()
            BREAK
    
    // 调用深度
    features.call_depth = CalculateReachabilityDepth(branch, merged_profile)
    
    RETURN features

// 2.6 约束分类（基于特征匹配）
FUNCTION ClassifyConstraint(
    constraint: ImportantConstraint,
    merged_profile: MergedProjectProfile,
    debug_info: DebugInfo
) -> ConstraintType:
    
    // 提取特征
    features = ExtractConstraintFeatures(
        GetBranchById(constraint.branch_id, merged_profile),
        debug_info,
        merged_profile
    )
    
    // 按优先级匹配
    
    // 优先级1: 哈希/校验
    IF features.has_hash_check:
        IF features.hash_type == "md5":
            RETURN ConstraintType.MD5_HASH_CHECK
        IF features.hash_type == "sha1":
            RETURN ConstraintType.SHA1_HASH_CHECK
        IF features.hash_type == "sha256":
            RETURN ConstraintType.SHA256_HASH_CHECK
        IF features.hash_type == "crc32":
            RETURN ConstraintType.CRC_CHECKSUM
        RETURN ConstraintType.SIMPLE_CHECKSUM
    
    // 优先级2: 格式
    IF features.format_type:
        IF features.format_type == "json":
            RETURN ConstraintType.JSON_FORMAT
        IF features.format_type == "xml":
            RETURN ConstraintType.XML_FORMAT
        IF features.format_type == "url":
            RETURN ConstraintType.URL_FORMAT
    
    // 优先级3: 字符串匹配
    IF features.has_string_comparison:
        (min_len, max_len) = features.string_length_range
        IF max_len <= 10:
            RETURN ConstraintType.SHORT_STRING_MATCH
        IF max_len <= 50:
            RETURN ConstraintType.MEDIUM_STRING_MATCH
        RETURN ConstraintType.LONG_STRING_MATCH
    
    // 优先级4: 长度约束
    IF features.has_length_check:
        IF features.length_check_type == "fixed":
            RETURN ConstraintType.FIXED_LENGTH_CHECK
        IF features.length_check_type == "min":
            RETURN ConstraintType.MIN_LENGTH_CHECK
        IF features.length_check_type == "max":
            RETURN ConstraintType.MAX_LENGTH_CHECK
    
    // 优先级5: 数值范围
    IF features.has_numeric_comparison:
        (min_val, max_val) = features.numeric_range
        range_size = max_val - min_val
        IF range_size <= 100:
            IF features.has_modulo:
                RETURN ConstraintType.MODULO_CHECK
            RETURN ConstraintType.SMALL_NUMERIC_RANGE
        IF range_size <= 10000:
            RETURN ConstraintType.MEDIUM_NUMERIC_RANGE
        RETURN ConstraintType.LARGE_NUMERIC_RANGE
    
    // 优先级6: 算术约束
    IF features.has_arithmetic_operation:
        IF features.arithmetic_complexity == 1:
            RETURN ConstraintType.LINEAR_ARITHMETIC
        RETURN ConstraintType.NONLINEAR_ARITHMETIC
    
    // 优先级7: 路径深度
    IF features.call_depth > 7:
        RETURN ConstraintType.DEEP_PATH
    IF features.call_depth > 3:
        RETURN ConstraintType.MEDIUM_PATH
    IF features.call_depth > 0:
        RETURN ConstraintType.SHALLOW_PATH
    
    RETURN ConstraintType.GENERAL_CONSTRAINT

// 2.7 模糊器能力矩阵（预定义）
FUNCTION InitializeFuzzerCapabilities() -> Dict[FuzzerType, Dict[ConstraintType, float]]:
    
    RETURN {
        FuzzerType.AFL: {
            ConstraintType.SHORT_STRING_MATCH: 0.8,
            ConstraintType.SMALL_NUMERIC_RANGE: 0.9,
            ConstraintType.SHALLOW_PATH: 0.8,
            ConstraintType.LINEAR_ARITHMETIC: 0.5,
            ConstraintType.GENERAL_CONSTRAINT: 0.5
        },
        FuzzerType.LIBFUZZER: {
            ConstraintType.SHORT_STRING_MATCH: 0.9,
            ConstraintType.MEDIUM_STRING_MATCH: 0.8,
            ConstraintType.JSON_FORMAT: 0.7,
            ConstraintType.REGEX_PATTERN: 0.6,
            ConstraintType.GENERAL_CONSTRAINT: 0.6
        },
        FuzzerType.AFLPLUSPLUS: {
            ConstraintType.SHORT_STRING_MATCH: 0.8,
            ConstraintType.SMALL_NUMERIC_RANGE: 0.8,
            ConstraintType.MEDIUM_PATH: 0.7,
            ConstraintType.GENERAL_CONSTRAINT: 0.7
        },
        FuzzerType.HONGGFUZZ: {
            ConstraintType.SMALL_NUMERIC_RANGE: 0.9,
            ConstraintType.MEDIUM_NUMERIC_RANGE: 0.8,
            ConstraintType.LINEAR_ARITHMETIC: 0.8,
            ConstraintType.GENERAL_CONSTRAINT: 0.6
        },
        FuzzerType.REDQUEEN: {
            ConstraintType.SHORT_STRING_MATCH: 0.95,
            ConstraintType.MEDIUM_STRING_MATCH: 0.8,
            ConstraintType.GENERAL_CONSTRAINT: 0.5
        },
        FuzzerType.LAF_INTEL: {
            ConstraintType.FIXED_LENGTH_CHECK: 0.9,
            ConstraintType.ARRAY_BOUNDS_CHECK: 0.9,
            ConstraintType.GENERAL_CONSTRAINT: 0.6
        },
        // ... 其他模糊器
        DEFAULT_CAPABILITY: 0.5
    }

// 2.8 动态权重更新
FUNCTION UpdateFuzzerWeights(
    base_capabilities: Dict[FuzzerType, Dict[ConstraintType, float]],
    recent_discoveries: List[ConstraintDiscovery],
    learning_rate: float = 0.3
) -> Dict[FuzzerType, Dict[ConstraintType, float]]:
    
    weights = DEEP_COPY(base_capabilities)
    stats = {}  // (fuzzer, constraint_type) -> (success, total)
    
    // 统计最近发现
    FOR EACH discovery IN recent_discoveries:
        key = (discovery.fuzzer_type, discovery.constraint_type)
        IF key NOT IN stats:
            stats[key] = (0, 0)
        (success, total) = stats[key]
        stats[key] = (success + 1, total + 1)
    
    // 更新权重
    FOR EACH (fuzzer, constraint_type) IN stats:
        (success_count, total_attempts) = stats[(fuzzer, constraint_type)]
        
        IF total_attempts >= MIN_ATTEMPTS:
            success_rate = success_count / total_attempts
            base_weight = base_capabilities[fuzzer].get(
                constraint_type,
                base_capabilities[fuzzer][DEFAULT_CAPABILITY]
            )
            new_weight = learning_rate * success_rate + (1 - learning_rate) * base_weight
            weights[fuzzer][constraint_type] = new_weight
    
    RETURN weights

// 2.9 匹配模糊器到约束组
FUNCTION MatchFuzzersToGroups(
    constraint_groups: List[ConstraintGroup],
    fuzzer_weights: Dict[FuzzerType, Dict[ConstraintType, float]],
    merged_profile: MergedProjectProfile,
    debug_info: DebugInfo
) -> Dict[FuzzerType, List[ConstraintGroup]]:
    
    assignments = {}
    FOR EACH fuzzer IN FuzzerType:
        assignments[fuzzer] = []
    
    FOR EACH group IN constraint_groups:
        // 分类组中的约束
        constraint_types = []
        FOR EACH constraint IN group.constraints:
            constraint_type = ClassifyConstraint(
                constraint, merged_profile, debug_info
            )
            constraint_types.append(constraint_type)
        
        // 计算每个模糊器的匹配分数
        best_fuzzer = None
        best_score = 0.0
        
        FOR EACH fuzzer IN FuzzerType:
            // 计算平均权重
            total_weight = 0.0
            FOR EACH constraint_type IN constraint_types:
                weight = fuzzer_weights[fuzzer].get(
                    constraint_type,
                    fuzzer_weights[fuzzer][DEFAULT_CAPABILITY]
                )
                total_weight += weight
            
            avg_weight = total_weight / len(constraint_types) IF len(constraint_types) > 0 ELSE 0.0
            
            // 组大小奖励
            group_bonus = LOG(1 + len(group.constraints)) / LOG(MAX_GROUP_SIZE)
            final_score = avg_weight * (1 + GROUP_SIZE_WEIGHT * group_bonus)
            
            IF final_score > best_score:
                best_score = final_score
                best_fuzzer = fuzzer
        
        IF best_fuzzer is not None:
            assignments[best_fuzzer].append(group)
    
    RETURN assignments


// ============================================
// 模块三：定向种子管理模块
// ============================================

// 3.1 种子结构
STRUCT Seed:
    seed_id: str
    data: bytes
    distance: float
    covered_functions: Set[str]
    covered_branches: Set[str]

// 3.2 计算种子到约束组的距离（仅调用路径）
FUNCTION CalculateSeedToGroupDistance(
    seed: Seed,
    group: ConstraintGroup,
    merged_profile: MergedProjectProfile,
    coverage_data: CoverageProfile
) -> float:
    
    // 获取种子覆盖的函数
    covered_functions = seed.covered_functions
    IF len(covered_functions) == 0:
        covered_functions = GetSeedCoveredFunctions(seed, coverage_data)
    
    // 目标函数（组中的主函数）
    target_function = group.main_function
    
    // 如果已覆盖目标函数，距离为0
    IF target_function IN covered_functions:
        RETURN 0.0
    
    // 计算调用路径距离（使用调用树）
    min_distance = INFINITY
    
    FOR EACH covered_func IN covered_functions:
        // 在调用树中查找最短路径深度
        path_depth = FindShortestPathDepth(
            covered_func,
            target_function,
            merged_profile.calltree
        )
        
        IF path_depth < INFINITY:
            min_distance = MIN(min_distance, path_depth)
    
    // 如果找不到路径，返回最大距离
    IF min_distance == INFINITY:
        RETURN MAX_DISTANCE
    
    RETURN min_distance

// 3.3 快速查找调用路径深度（BFS，O(V+E)）
FUNCTION FindShortestPathDepth(
    source_func: str,
    target_func: str,
    calltree: CalltreeNode
) -> int:
    
    // BFS搜索
    queue = [(source_func, 0)]  // (function, depth)
    visited = {source_func}
    
    WHILE queue is not empty:
        (current_func, depth) = queue.pop(0)
        
        IF current_func == target_func:
            RETURN depth
        
        // 获取直接调用的函数
        callees = GetDirectCallees(current_func, calltree)
        
        FOR EACH callee IN callees:
            IF callee NOT IN visited:
                visited.add(callee)
                queue.append((callee, depth + 1))
    
    RETURN INFINITY

// 3.4 快速种子修剪（只保留距离近的）
FUNCTION PruneSeedsByDistance(
    seed_queue: List[Seed],
    target_groups: List[ConstraintGroup],
    merged_profile: MergedProjectProfile,
    coverage_data: CoverageProfile,
    max_distance: int  // 最大调用深度
) -> List[Seed]:
    
    pruned_seeds = []
    
    FOR EACH seed IN seed_queue:
        // 计算到最近目标组的距离
        min_group_distance = INFINITY
        
        FOR EACH group IN target_groups:
            distance = CalculateSeedToGroupDistance(
                seed, group, merged_profile, coverage_data
            )
            min_group_distance = MIN(min_group_distance, distance)
        
        // 只保留距离在阈值内的种子
        IF min_group_distance <= max_distance:
            seed.distance = min_group_distance
            pruned_seeds.append(seed)
    
    // 按距离排序（距离近的优先）
    SORT(pruned_seeds, key=seed.distance)
    
    RETURN pruned_seeds

// 3.5 提取简单字典（只提取字符串常量）
FUNCTION ExtractSimpleDictionary(
    constraint_group: ConstraintGroup,
    merged_profile: MergedProjectProfile,
    debug_info: DebugInfo
) -> List[str]:
    
    dictionary = []
    
    // 从约束分支中提取字符串常量
    FOR EACH constraint IN constraint_group.constraints:
        branch = GetBranchById(constraint.branch_id, merged_profile)
        strings = ExtractStringConstants(branch, debug_info)
        dictionary.extend(strings)
    
    // 去重
    RETURN UNIQUE(dictionary)

// 3.6 周期性种子修剪
FUNCTION PeriodicSeedPruning(
    seed_queue: List[Seed],
    target_groups: List[ConstraintGroup],
    merged_profile: MergedProjectProfile,
    coverage_data: CoverageProfile,
    pruning_interval: int,
    max_distance: int
) -> List[Seed]:
    
    // 每隔一定时间执行修剪
    IF current_time % pruning_interval == 0:
        pruned_seeds = PruneSeedsByDistance(
            seed_queue,
            target_groups,
            merged_profile,
            coverage_data,
            max_distance
        )
        
        LOG("Pruned seeds: {original} -> {pruned}",
            original = len(seed_queue),
            pruned = len(pruned_seeds))
        
        RETURN pruned_seeds
    
    RETURN seed_queue