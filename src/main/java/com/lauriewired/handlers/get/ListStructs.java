package com.lauriewired.handlers.get;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.data.*;

import java.io.IOException;
import java.util.Iterator;

import static com.lauriewired.util.ParseUtils.sendResponse;
import static com.lauriewired.util.GhidraUtils.getCurrentProgram;

/**
 * Handler for listing all defined structures in the current program.
 * Returns struct names, sizes, and their fields/components.
 * Filters out undefined fields for cleaner output.
 */
public class ListStructs extends Handler {
    public ListStructs(PluginTool tool) {
        super(tool, "/list_structs");
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        sendResponse(exchange, listStructs());
    }

    /**
     * Lists all defined structures in the current program.
     * Only includes structs in the root category (/).
     * Filters out undefined field types.
     *
     * @return A formatted string containing all struct definitions
     */
    private String listStructs() {
        try {
            Program program = getCurrentProgram(tool);
            if (program == null) {
                return "No program loaded";
            }

            DataTypeManager dtm = program.getDataTypeManager();
            StringBuilder result = new StringBuilder();
            int structCount = 0;

            // Iterate through all data types and filter for structures
            Iterator<DataType> dtIterator = dtm.getAllDataTypes();
            while (dtIterator.hasNext()) {
                DataType dt = dtIterator.next();
                if (dt instanceof Structure) {
                    Structure struct = (Structure) dt;

                    // Only include structs in the root category (/)
                    String categoryPath = struct.getCategoryPath().getPath();
                    if (!categoryPath.equals("/")) {
                        continue;
                    }

                    structCount++;

                    // Struct header
                    result.append("struct ").append(struct.getName())
                          .append(" { // size: ").append(struct.getLength()).append(" bytes\n");

                    // Log each field/component
                    if (struct.getNumComponents() > 0) {
                        for (DataTypeComponent component : struct.getComponents()) {
                            String fieldName = component.getFieldName();
                            DataType fieldType = component.getDataType();

                            // Skip undefined fields
                            if (fieldType == null ||
                                fieldType instanceof Undefined ||
                                "undefined".equalsIgnoreCase(fieldType.getName())) {
                                continue;
                            }

                            // Use <unnamed> for fields without names
                            if (fieldName == null || fieldName.isEmpty()) {
                                fieldName = "<unnamed>";
                            }

                            // Format: [offset] fieldName: type (size)
                            result.append("  [+0x")
                                  .append(String.format("%x", component.getOffset()))
                                  .append("] ")
                                  .append(fieldName)
                                  .append(": ")
                                  .append(fieldType.getName())
                                  .append(" (size: ")
                                  .append(component.getLength())
                                  .append(")\n");
                        }
                    }

                    result.append("}\n\n");
                }
            }

            if (structCount == 0) {
                return "No structs found in root category";
            }

            result.append("Total structs: ").append(structCount).append("\n");
            return result.toString();

        } catch (Exception e) {
            return "Error listing structs: " + e.getMessage();
        }
    }
}
