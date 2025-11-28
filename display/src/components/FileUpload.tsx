import { useRef, useState } from 'react'
import { Button } from './ui/button'

interface FileUploadProps {
  onFilesSelected: (files: File[]) => void
  onFolderSelected: (files: File[]) => void
  disabled: boolean
}

export function FileUpload({ onFilesSelected, onFolderSelected, disabled }: FileUploadProps) {
  const fileInputRef = useRef<HTMLInputElement>(null)
  const folderInputRef = useRef<HTMLInputElement>(null)
  const [selectedFiles, setSelectedFiles] = useState<File[]>([])

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(e.target.files || [])
    setSelectedFiles(files)
    onFilesSelected(files)
  }

  const handleFolderSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(e.target.files || [])
    setSelectedFiles(files)
    onFolderSelected(files)
  }

  const clearSelection = () => {
    setSelectedFiles([])
    if (fileInputRef.current) fileInputRef.current.value = ''
    if (folderInputRef.current) folderInputRef.current.value = ''
    onFilesSelected([])
  }

  return (
    <div className="p-4 border rounded-lg bg-white">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-semibold text-gray-700">Scan Files/Folders</h3>
        {selectedFiles.length > 0 && (
          <Button
            variant="outline"
            size="sm"
            onClick={clearSelection}
            disabled={disabled}
            className="text-xs"
          >
            Clear ({selectedFiles.length})
          </Button>
        )}
      </div>
      
      <div className="flex gap-2">
        <input
          ref={fileInputRef}
          type="file"
          multiple
          onChange={handleFileSelect}
          disabled={disabled}
          className="hidden"
          id="file-upload"
          accept="*/*"
        />
        <Button
          variant="outline"
          size="sm"
          disabled={disabled}
          className="text-xs cursor-pointer"
          onClick={() => fileInputRef.current?.click()}
        >
          Add Files
        </Button>

        <input
          ref={folderInputRef}
          type="file"
          multiple
          {...({ webkitdirectory: '', directory: '' } as any)}
          onChange={handleFolderSelect}
          disabled={disabled}
          className="hidden"
          id="folder-upload"
        />
        <Button
          variant="outline"
          size="sm"
          disabled={disabled}
          className="text-xs cursor-pointer"
          onClick={() => folderInputRef.current?.click()}
        >
          Add Folder
        </Button>
      </div>

      {selectedFiles.length > 0 && (
        <div className="mt-3 text-xs text-gray-600">
          <p className="font-medium mb-1">Selected: {selectedFiles.length} file(s)</p>
          <div className="max-h-32 overflow-y-auto space-y-1">
            {selectedFiles.slice(0, 5).map((file, idx) => (
              <div key={idx} className="truncate">
                {file.name}
              </div>
            ))}
            {selectedFiles.length > 5 && (
              <div className="text-gray-500">... and {selectedFiles.length - 5} more</div>
            )}
          </div>
        </div>
      )}

      <p className="mt-2 text-xs text-gray-500">
        {selectedFiles.length === 0 
          ? "No files selected. Simulator will use default dataset."
          : "Selected files will be scanned instead of default dataset."}
      </p>
    </div>
  )
}

