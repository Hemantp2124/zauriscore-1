"""Utility functions for file operations."""
import hashlib
import json
import os
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional, Union, BinaryIO, TextIO

from ..config import config
from ..utils.logger import setup_logger

logger = setup_logger("utils.files")

def ensure_directory(path: Union[str, Path]) -> Path:
    """Ensure a directory exists, creating it if necessary.
    
    Args:
        path: Directory path
        
    Returns:
        Path object for the directory
    """
    path = Path(path).resolve()
    path.mkdir(parents=True, exist_ok=True)
    return path

def read_json(file_path: Union[str, Path]) -> Any:
    """Read and parse a JSON file.
    
    Args:
        file_path: Path to the JSON file
        
    Returns:
        Parsed JSON data
    """
    file_path = Path(file_path)
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def write_json(
    data: Any, 
    file_path: Union[str, Path], 
    indent: int = 2,
    ensure_ascii: bool = False
) -> Path:
    """Write data to a JSON file.
    
    Args:
        data: Data to write
        file_path: Path to the output file
        indent: Indentation level
        ensure_ascii: Whether to escape non-ASCII characters
        
    Returns:
        Path to the written file
    """
    file_path = Path(file_path)
    ensure_directory(file_path.parent)
    
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(
            data, 
            f, 
            indent=indent, 
            ensure_ascii=ensure_ascii,
            default=str  # Handle non-serializable types
        )
    
    return file_path

def file_hash(file_path: Union[str, Path], algorithm: str = 'sha256') -> str:
    """Calculate the hash of a file.
    
    Args:
        file_path: Path to the file
        algorithm: Hash algorithm (default: sha256)
        
    Returns:
        Hexadecimal digest of the file
    """
    file_path = Path(file_path)
    hasher = hashlib.new(algorithm)
    
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hasher.update(chunk)
    
    return hasher.hexdigest()

def find_files(
    directory: Union[str, Path],
    patterns: Union[str, List[str]] = '*',
    recursive: bool = True,
    ignore_dirs: Optional[List[str]] = None
) -> List[Path]:
    """Find files matching the given patterns.
    
    Args:
        directory: Directory to search in
        patterns: File patterns to match (e.g., '*.py' or ['*.py', '*.txt'])
        recursive: Whether to search recursively
        ignore_dirs: Directory names to ignore
        
    Returns:
        List of matching file paths
    """
    directory = Path(directory)
    if not directory.is_dir():
        raise NotADirectoryError(f"Directory not found: {directory}")
    
    if isinstance(patterns, str):
        patterns = [patterns]
    
    ignore_dirs = set(ignore_dirs or [])
    matches = []
    
    for pattern in patterns:
        if recursive:
            for path in directory.rglob(pattern):
                if not any(part in ignore_dirs for part in path.parts):
                    matches.append(path.resolve())
        else:
            for path in directory.glob(pattern):
                if not any(part in ignore_dirs for part in path.parts):
                    matches.append(path.resolve())
    
    return sorted(set(matches))

def copy_file(
    src: Union[str, Path],
    dst: Union[str, Path],
    overwrite: bool = False
) -> Path:
    """Copy a file from source to destination.
    
    Args:
        src: Source file path
        dst: Destination path (can be a directory or file)
        overwrite: Whether to overwrite if destination exists
        
    Returns:
        Path to the destination file
    """
    src = Path(src)
    dst = Path(dst)
    
    if not src.is_file():
        raise FileNotFoundError(f"Source file not found: {src}")
    
    if dst.is_dir():
        dst = dst / src.name
    
    if dst.exists() and not overwrite:
        raise FileExistsError(f"Destination file exists: {dst}")
    
    ensure_directory(dst.parent)
    shutil.copy2(src, dst)
    return dst.resolve()

def delete_file(file_path: Union[str, Path]) -> None:
    """Delete a file if it exists.
    
    Args:
        file_path: Path to the file to delete
    """
    file_path = Path(file_path)
    if file_path.exists():
        file_path.unlink()

def clear_directory(directory: Union[str, Path]) -> None:
    """Remove all files and subdirectories in a directory.
    
    Args:
        directory: Directory to clear
    """
    directory = Path(directory)
    if not directory.exists():
        return
    
    for item in directory.iterdir():
        if item.is_dir():
            shutil.rmtree(item)
        else:
            item.unlink()

def create_temp_file(
    content: Union[str, bytes],
    suffix: str = '.tmp',
    directory: Optional[Union[str, Path]] = None
) -> Path:
    """Create a temporary file with the given content.
    
    Args:
        content: File content (str or bytes)
        suffix: File suffix
        directory: Directory to create the file in (default: system temp dir)
        
    Returns:
        Path to the created file
    """
    import tempfile
    
    mode = 'w' if isinstance(content, str) else 'wb'
    encoding = 'utf-8' if isinstance(content, str) else None
    
    if directory is not None:
        directory = Path(directory)
        ensure_directory(directory)
    
    with tempfile.NamedTemporaryFile(
        mode=mode,
        suffix=suffix,
        dir=str(directory) if directory else None,
        delete=False,
        encoding=encoding
    ) as f:
        f.write(content)
        return Path(f.name)
