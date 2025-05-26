"""
Project Walker for Crypto Hunter
Generates a helicopter view of the entire project structure, functions, and classes.
"""

import ast
import os
import json
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
import argparse

@dataclass
class FunctionInfo:
    name: str
    signature: str
    docstring: Optional[str]
    line_number: int
    is_async: bool = False
    decorators: List[str] = None
    
    def __post_init__(self):
        if self.decorators is None:
            self.decorators = []

@dataclass
class ClassInfo:
    name: str
    docstring: Optional[str]
    line_number: int
    methods: List[FunctionInfo]
    base_classes: List[str] = None
    decorators: List[str] = None
    
    def __post_init__(self):
        if self.base_classes is None:
            self.base_classes = []
        if self.decorators is None:
            self.decorators = []

@dataclass
class ModuleInfo:
    name: str
    path: str
    docstring: Optional[str]
    imports: List[str]
    functions: List[FunctionInfo]
    classes: List[ClassInfo]
    constants: List[str]
    file_size: int
    line_count: int

class ProjectWalker:
    """
    Walks through a Python project and extracts structural information.
    """
    
    def __init__(self, root_path: str, exclude_dirs: List[str] = None, exclude_files: List[str] = None):
        self.root_path = Path(root_path)
        self.exclude_dirs = exclude_dirs or [
            '__pycache__', '.git', '.pytest_cache', 'node_modules', 
            '.venv', 'venv', 'env', '.env', 'build', 'dist'
        ]
        self.exclude_files = exclude_files or [
            '__init__.py'  # Often just imports, not much content
        ]
        
    def extract_signature(self, node: ast.FunctionDef) -> str:
        """Extract function signature as string."""
        args = []
        
        # Regular arguments
        for arg in node.args.args:
            arg_str = arg.arg
            if arg.annotation:
                arg_str += f": {ast.unparse(arg.annotation)}"
            args.append(arg_str)
        
        # *args
        if node.args.vararg:
            vararg_str = f"*{node.args.vararg.arg}"
            if node.args.vararg.annotation:
                vararg_str += f": {ast.unparse(node.args.vararg.annotation)}"
            args.append(vararg_str)
        
        # **kwargs
        if node.args.kwarg:
            kwarg_str = f"**{node.args.kwarg.arg}"
            if node.args.kwarg.annotation:
                kwarg_str += f": {ast.unparse(node.args.kwarg.annotation)}"
            args.append(kwarg_str)
        
        # Keyword-only arguments
        if node.args.kwonlyargs:
            if not node.args.vararg:
                args.append("*")
            for arg in node.args.kwonlyargs:
                arg_str = arg.arg
                if arg.annotation:
                    arg_str += f": {ast.unparse(arg.annotation)}"
                args.append(arg_str)
        
        signature = f"({', '.join(args)})"
        
        # Return type annotation
        if node.returns:
            signature += f" -> {ast.unparse(node.returns)}"
            
        return signature
    
    def extract_decorators(self, node) -> List[str]:
        """Extract decorator names."""
        decorators = []
        for decorator in node.decorator_list:
            try:
                decorators.append(ast.unparse(decorator))
            except:
                decorators.append(str(decorator))
        return decorators
    
    def extract_docstring(self, node) -> Optional[str]:
        """Extract docstring from a node."""
        if (isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module)) and
            node.body and isinstance(node.body[0], ast.Expr) and
            isinstance(node.body[0].value, ast.Constant) and
            isinstance(node.body[0].value.value, str)):
            return node.body[0].value.value
        return None
    
    def extract_imports(self, tree: ast.AST) -> List[str]:
        """Extract import statements."""
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(f"import {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    imports.append(f"from {module} import {alias.name}")
        return imports
    
    def extract_constants(self, tree: ast.AST) -> List[str]:
        """Extract module-level constants (uppercase variables)."""
        constants = []
        for node in tree.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id.isupper():
                        try:
                            value = ast.unparse(node.value)
                            constants.append(f"{target.id} = {value}")
                        except:
                            constants.append(f"{target.id} = <complex_value>")
        return constants
    
    def analyze_file(self, file_path: Path) -> Optional[ModuleInfo]:
        """Analyze a single Python file."""
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            tree = ast.parse(content)
            
            # Get file stats
            stat = file_path.stat()
            line_count = len(content.splitlines())
            
            # Extract module info
            module_name = file_path.stem
            if file_path.parent.name != self.root_path.name:
                # Include parent directory in module name
                parent_parts = file_path.parent.relative_to(self.root_path).parts
                module_name = ".".join(parent_parts + (module_name,))
            
            # Extract components
            docstring = self.extract_docstring(tree)
            imports = self.extract_imports(tree)
            constants = self.extract_constants(tree)
            
            functions = []
            classes = []
            
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    func_info = FunctionInfo(
                        name=node.name,
                        signature=self.extract_signature(node),
                        docstring=self.extract_docstring(node),
                        line_number=node.lineno,
                        is_async=isinstance(node, ast.AsyncFunctionDef),
                        decorators=self.extract_decorators(node)
                    )
                    functions.append(func_info)
                
                elif isinstance(node, ast.ClassDef):
                    # Extract class methods
                    methods = []
                    for class_node in node.body:
                        if isinstance(class_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            method_info = FunctionInfo(
                                name=class_node.name,
                                signature=self.extract_signature(class_node),
                                docstring=self.extract_docstring(class_node),
                                line_number=class_node.lineno,
                                is_async=isinstance(class_node, ast.AsyncFunctionDef),
                                decorators=self.extract_decorators(class_node)
                            )
                            methods.append(method_info)
                    
                    # Extract base classes
                    base_classes = []
                    for base in node.bases:
                        try:
                            base_classes.append(ast.unparse(base))
                        except:
                            base_classes.append(str(base))
                    
                    class_info = ClassInfo(
                        name=node.name,
                        docstring=self.extract_docstring(node),
                        line_number=node.lineno,
                        methods=methods,
                        base_classes=base_classes,
                        decorators=self.extract_decorators(node)
                    )
                    classes.append(class_info)
            
            return ModuleInfo(
                name=module_name,
                path=str(file_path.relative_to(self.root_path)),
                docstring=docstring,
                imports=imports,
                functions=functions,
                classes=classes,
                constants=constants,
                file_size=stat.st_size,
                line_count=line_count
            )
            
        except Exception as e:
            print(f"Error analyzing {file_path}: {e}")
            return None
    
    def walk_project(self) -> Dict[str, List[ModuleInfo]]:
        """Walk the entire project and extract information."""
        project_info = {
            "core_modules": [],
            "analyzers": [],
            "tools": [],
            "utilities": [],
            "other": []
        }
        
        for py_file in self.root_path.rglob("*.py"):
            # Skip excluded directories
            if any(excluded in py_file.parts for excluded in self.exclude_dirs):
                continue
            
            # Skip excluded files
            if py_file.name in self.exclude_files:
                continue
            
            module_info = self.analyze_file(py_file)
            if module_info:
                # Categorize the module
                if "core" in py_file.parts:
                    project_info["core_modules"].append(module_info)
                elif "analyzer" in py_file.name.lower() or "analyzers" in py_file.parts:
                    project_info["analyzers"].append(module_info)
                elif "tool" in py_file.name.lower() or "tools" in py_file.parts:
                    project_info["tools"].append(module_info)
                elif any(util in py_file.name.lower() for util in ["util", "helper", "config"]):
                    project_info["utilities"].append(module_info)
                else:
                    project_info["other"].append(module_info)
        
        return project_info
    
    def generate_summary(self, project_info: Dict[str, List[ModuleInfo]]) -> str:
        """Generate a human-readable summary."""
        summary = []
        summary.append("=" * 80)
        summary.append("CRYPTO HUNTER PROJECT OVERVIEW")
        summary.append("=" * 80)
        summary.append("")
        
        total_files = sum(len(modules) for modules in project_info.values())
        total_functions = sum(len(mod.functions) for modules in project_info.values() for mod in modules)
        total_classes = sum(len(mod.classes) for modules in project_info.values() for mod in modules)
        total_lines = sum(mod.line_count for modules in project_info.values() for mod in modules)
        
        summary.append(f"📊 PROJECT STATISTICS:")
        summary.append(f"   • Total Python files: {total_files}")
        summary.append(f"   • Total functions: {total_functions}")
        summary.append(f"   • Total classes: {total_classes}")
        summary.append(f"   • Total lines of code: {total_lines:,}")
        summary.append("")
        
        for category, modules in project_info.items():
            if not modules:
                continue
                
            summary.append(f"🔧 {category.upper().replace('_', ' ')} ({len(modules)} modules)")
            summary.append("-" * 60)
            
            for module in modules:
                summary.append(f"\n📄 {module.name} ({module.path})")
                if module.docstring:
                    doc_preview = module.docstring.split('\n')[0][:100]
                    summary.append(f"   📝 {doc_preview}...")
                
                summary.append(f"   📏 {module.line_count} lines, {module.file_size} bytes")
                
                if module.functions:
                    summary.append(f"   🔧 Functions ({len(module.functions)}):")
                    for func in module.functions[:5]:  # Show first 5 functions
                        signature = f"{func.name}{func.signature}"
                        if len(signature) > 80:
                            signature = signature[:77] + "..."
                        async_marker = "async " if func.is_async else ""
                        decorators = f"@{', @'.join(func.decorators)} " if func.decorators else ""
                        summary.append(f"      • {decorators}{async_marker}{signature}")
                        if func.docstring:
                            doc_preview = func.docstring.split('\n')[0][:60]
                            summary.append(f"        ↳ {doc_preview}...")
                    
                    if len(module.functions) > 5:
                        summary.append(f"      ... and {len(module.functions) - 5} more functions")
                
                if module.classes:
                    summary.append(f"   🏗️ Classes ({len(module.classes)}):")
                    for cls in module.classes:
                        inheritance = f"({', '.join(cls.base_classes)})" if cls.base_classes else ""
                        summary.append(f"      • {cls.name}{inheritance}")
                        if cls.docstring:
                            doc_preview = cls.docstring.split('\n')[0][:60]
                            summary.append(f"        ↳ {doc_preview}...")
                        
                        if cls.methods:
                            method_names = [m.name for m in cls.methods[:3]]
                            if len(cls.methods) > 3:
                                method_names.append(f"... +{len(cls.methods) - 3} more")
                            summary.append(f"        Methods: {', '.join(method_names)}")
                
                if module.constants:
                    summary.append(f"   🔢 Constants: {', '.join([c.split('=')[0].strip() for c in module.constants[:3]])}")
                
                summary.append("")
        
        return "\n".join(summary)
    
    def save_detailed_json(self, project_info: Dict[str, List[ModuleInfo]], output_file: str):
        """Save detailed project information as JSON."""
        # Convert to serializable format
        serializable_info = {}
        for category, modules in project_info.items():
            serializable_info[category] = [asdict(module) for module in modules]
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(serializable_info, f, indent=2, ensure_ascii=False)
    
    def create_function_index(self, project_info: Dict[str, List[ModuleInfo]]) -> str:
        """Create a searchable index of all functions and their purposes."""
        index = []
        index.append("=" * 80)
        index.append("FUNCTION INDEX - SEARCHABLE REFERENCE")
        index.append("=" * 80)
        index.append("")
        
        all_functions = []
        
        # Collect all functions from all modules
        for category, modules in project_info.items():
            for module in modules:
                # Module-level functions
                for func in module.functions:
                    all_functions.append({
                        'category': category,
                        'module': module.name,
                        'type': 'function',
                        'name': func.name,
                        'signature': f"{func.name}{func.signature}",
                        'docstring': func.docstring,
                        'decorators': func.decorators,
                        'is_async': func.is_async
                    })
                
                # Class methods
                for cls in module.classes:
                    for method in cls.methods:
                        all_functions.append({
                            'category': category,
                            'module': module.name,
                            'type': 'method',
                            'class': cls.name,
                            'name': method.name,
                            'signature': f"{method.name}{method.signature}",
                            'docstring': method.docstring,
                            'decorators': method.decorators,
                            'is_async': method.is_async
                        })
        
        # Sort by category and then by name
        all_functions.sort(key=lambda x: (x['category'], x['name']))
        
        current_category = None
        for func in all_functions:
            if func['category'] != current_category:
                current_category = func['category']
                index.append(f"\n🔧 {current_category.upper().replace('_', ' ')}")
                index.append("-" * 50)
            
            # Function signature with context
            context = f"{func['module']}"
            if func['type'] == 'method':
                context += f".{func['class']}"
            
            async_marker = "async " if func.get('is_async') else ""
            decorators = f"@{', @'.join(func['decorators'])} " if func.get('decorators') else ""
            
            index.append(f"\n  {decorators}{async_marker}{func['signature']}")
            index.append(f"    📍 {context}")
            
            if func['docstring']:
                # Extract purpose from docstring (first line usually contains the purpose)
                purpose = func['docstring'].split('\n')[0].strip()
                if purpose:
                    index.append(f"    💡 {purpose}")
        
        return "\n".join(index)

def main():
    parser = argparse.ArgumentParser(description="Analyze Python project structure for Crypto Hunter")
    parser.add_argument("path", nargs="?", default=".", help="Path to project root (default: current directory)")
    parser.add_argument("--output", "-o", default="project_overview.txt", help="Output file for summary")
    parser.add_argument("--json", help="Output file for detailed JSON")
    parser.add_argument("--index", help="Output file for function index")
    parser.add_argument("--exclude-dirs", nargs="*", help="Additional directories to exclude")
    parser.add_argument("--exclude-files", nargs="*", help="Additional files to exclude")
    
    args = parser.parse_args()
    
    # Initialize walker
    walker = ProjectWalker(
        args.path, 
        exclude_dirs=args.exclude_dirs,
        exclude_files=args.exclude_files
    )
    
    print("🔍 Analyzing project structure...")
    project_info = walker.walk_project()
    
    print("📝 Generating summary...")
    summary = walker.generate_summary(project_info)
    
    # Save summary
    with open(args.output, 'w', encoding='utf-8') as f:
        f.write(summary)
    print(f"✅ Summary saved to: {args.output}")
    
    # Save JSON if requested
    if args.json:
        walker.save_detailed_json(project_info, args.json)
        print(f"✅ Detailed JSON saved to: {args.json}")
    
    # Save function index if requested
    if args.index:
        index = walker.create_function_index(project_info)
        with open(args.index, 'w', encoding='utf-8') as f:
            f.write(index)
        print(f"✅ Function index saved to: {args.index}")
    
    # Print summary to console
    print("\n" + summary)

if __name__ == "__main__":
    main()
