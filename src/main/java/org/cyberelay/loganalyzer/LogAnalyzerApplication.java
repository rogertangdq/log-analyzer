package org.cyberelay.loganalyzer;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class LogAnalyzerApplication implements CommandLineRunner {

	public static void main(String[] args) {
		SpringApplication.run(LogAnalyzerApplication.class, args);
	}

	@Override
	public void run(String... args) {
		var options = new Options();
		var input = Option.builder("i")
				.longOpt("input")
				.desc("input log file path (default: log.csv)")
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
				.desc("lookup file path (default: lookup.csv)")
				.hasArg(true)
				.required(true)
				.build();
		options.addOption(input).addOption(output).addOption(lookup);

		var parser = new DefaultParser();
		var formatter = new HelpFormatter();
		CommandLine cmd;

		try {
			cmd = parser.parse(options, args);
			String inputFilePath = cmd.getOptionValue("input", "log.txt");
			String outputFilePath = cmd.getOptionValue("output", "output.txt");
			String lookupFilePath = cmd.getOptionValue("lookup", "lookup.csv");

			// parse the input/lookup data files, generate stats and write them into output file
			new LogStatsCollector(lookupFilePath).collect(inputFilePath, outputFilePath);
		} catch (ParseException e) {
			System.out.println(e.getMessage());
			formatter.printHelp("Log-analyzer", options);
			System.exit(1);
		}
	}
}
