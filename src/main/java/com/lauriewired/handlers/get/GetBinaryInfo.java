package com.lauriewired.handlers.get;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.CompilerSpec;

import java.io.IOException;
import java.io.File;
import java.io.FileInputStream;
import java.security.MessageDigest;

import static com.lauriewired.util.ParseUtils.sendResponse;
import static com.lauriewired.util.GhidraUtils.getCurrentProgram;

/**
 * Handler for GET requests to retrieve binary/program information.
 * Returns metadata about the currently loaded binary including hashes,
 * file path, architecture, and other useful details.
 */
public class GetBinaryInfo extends Handler {
    public GetBinaryInfo(PluginTool tool) {
        super(tool, "/get_binary_info");
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        sendResponse(exchange, getBinaryInfo());
    }

    /**
     * Retrieves comprehensive information about the current binary.
     *
     * @return A formatted string containing binary metadata
     */
    private String getBinaryInfo() {
        try {
            Program program = getCurrentProgram(tool);
            if (program == null) {
                return "No program loaded";
            }

            StringBuilder info = new StringBuilder();

            // File path
            String executablePath = program.getExecutablePath();
            info.append("File Path: ").append(executablePath != null ? executablePath : "Unknown").append("\n");

            // Calculate hashes if file exists
            if (executablePath != null) {
                File file = new File(executablePath);
                if (file.exists()) {
                    info.append("File Size: ").append(formatFileSize(file.length())).append("\n");

                    String md5 = calculateHash(file, "MD5");
                    String sha1 = calculateHash(file, "SHA-1");
                    String sha256 = calculateHash(file, "SHA-256");

                    info.append("MD5: ").append(md5).append("\n");
                    info.append("SHA1: ").append(sha1).append("\n");
                    info.append("SHA256: ").append(sha256).append("\n");
                }
            }

            // Program name
            info.append("Program Name: ").append(program.getName()).append("\n");

            // Executable format
            info.append("Executable Format: ").append(program.getExecutableFormat()).append("\n");

            return info.toString();

        } catch (Exception e) {
            return "Error retrieving binary info: " + e.getMessage();
        }
    }

    /**
     * Calculates the hash of a file using the specified algorithm.
     *
     * @param file The file to hash
     * @param algorithm The hash algorithm (MD5, SHA-1, SHA-256)
     * @return The hash as a hex string, or "Error" if calculation fails
     */
    private String calculateHash(File file, String algorithm) {
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            FileInputStream fis = new FileInputStream(file);
            byte[] byteArray = new byte[8192];
            int bytesRead;

            while ((bytesRead = fis.read(byteArray)) != -1) {
                digest.update(byteArray, 0, bytesRead);
            }
            fis.close();

            byte[] hashBytes = digest.digest();
            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();

        } catch (Exception e) {
            return "Error calculating " + algorithm;
        }
    }

    /**
     * Formats a file size in bytes to a human-readable string.
     *
     * @param bytes The size in bytes
     * @return Formatted string (e.g., "1.5 MB")
     */
    private String formatFileSize(long bytes) {
        if (bytes < 1024) return bytes + " B";
        int exp = (int) (Math.log(bytes) / Math.log(1024));
        String pre = "KMGTPE".charAt(exp - 1) + "";
        return String.format("%.2f %sB", bytes / Math.pow(1024, exp), pre);
    }
}
