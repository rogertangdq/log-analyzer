package org.cyberelay.loganalyzer;

import com.google.common.collect.HashMultimap;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVRecord;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.io.FileReader;
import java.io.Reader;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@SpringBootApplication
public class LogAnalyzerApplication implements CommandLineRunner {

	public static void main(String[] args) {
		SpringApplication.run(LogAnalyzerApplication.class, args);
	}

	@Override
	public void run(String... args) throws Exception {
		var options = new Options();
		var input = Option.builder("i")
				.longOpt("input")
				.desc("input log file path (default: input.csv)")
				.hasArg(true)
				.required(true)
				.build();
		var output = Option.builder("o")
				.longOpt("output")
				.desc("output file path (default: output.txt)")
				.hasArg(true)
				.required(true)
				.build();
		var lookup = Option.builder("l")
				.longOpt("lookup")
				.desc("lookup file path (default: lookup.txt)")
				.hasArg(true)
				.required(true)
				.build();
		options.addOption(input).addOption(output).addOption(lookup);

		var parser = new DefaultParser();
		var formatter = new HelpFormatter();
		CommandLine cmd;

		try {
			cmd = parser.parse(options, args);
			String inputFilePath = cmd.getOptionValue("input");
			String outputFilePath = cmd.getOptionValue("output");

			System.out.println("Input File: " + inputFilePath);
			System.out.println("Output File: " + outputFilePath);
		} catch (ParseException e) {
			System.out.println(e.getMessage());
			formatter.printHelp("Log-analyzer", options);

			System.exit(1);
		}
	}

	private HashMultimap<LookupEntryKey, String> parseLookupTable(String filePath) {
		HashMultimap<LookupEntryKey, String> result = HashMultimap.create();

		try (Reader reader = new FileReader(filePath)) {
			CSVFormat.DEFAULT
					.builder()
					.setSkipHeaderRecord(true) // Optional: skip the header row
					.build()
					.parse(reader)
					.forEach(record -> {
						var port = Optional
								.ofNullable(record.get("dstport"))
								.orElseThrow(() -> new RuntimeException("dstport column not found in " + filePath));
						var protocol = Optional
								.ofNullable(record.get("protocol"))
								.orElseThrow(() -> new RuntimeException("protocol column not found in " + filePath));
						var tag = Optional
								.ofNullable(record.get("tag"))
								.orElseThrow(() -> new RuntimeException("tag column not found in " + filePath));
						var entry = new LookupEntryKey(port, protocol);

						result.put(entry, tag);
					});
		} catch (Exception e) {
			throw new RuntimeException("Lookup table file error: " + e.getMessage(), e);
		}

		return result;
	}

	record LookupEntryKey(String port, String protocol) {}
}
