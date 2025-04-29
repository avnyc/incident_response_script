import ahocorasick
import datetime
from file_locations_and_log_settings import ir_logger, ir_logfile, ir_output_file, ir_main_file
from mitre_attack_builder import mitre_attck_df
from multistep_phrases_to_delete import multistep_phrases_to_delete
import numpy as np
import pandas as pd
import re
import swifter
from sysmon_and_event_log_phrases_to_delete import sysmon_and_event_log_phrases_to_delete
import time
from tqdm.auto import tqdm

############ Change the following to match your environment!
# I have three columns.
# I have different log sources in the log_source column

timestamp = 'timestamp'
log_source = 'log_source'
json_column_with_logs = 'raw_logs'
sysmon_and_event_log_source_is_called = 'sysmon_and_event_logs'
columns_needed  = [timestamp, log_source, json_column_with_logs]

# Adjust this to your SIEM logs
# timestamp	log_source	raw_logs
# 2025-04-26T13:45:40+00:00	sysmon_and_event_logs   json formatted logs here - very easy to read without manipulation

###################################################################

# Ensure tqdm works with swifter
tqdm.pandas(desc="Running progress_apply")

# Make sure the dataframe is completely visible
pd.set_option('display.max_rows', None)
pd.set_option('display.max_columns', None)
pd.set_option('expand_frame_repr', False)
pd.set_option('display.width', None)
pd.set_option('display.max_colwidth', None)

class IR_MITRE_ATTCK():

    def __init__(self,
                 multistep_phrases_to_delete,
                 sysmon_and_event_log_phrases_to_delete,
                 mitre_attck_df):

        # Start timer
        self.start = time.time()

        # Initialize input parameters
        self.multistep_phrases_to_delete = multistep_phrases_to_delete
        self.sysmon_and_event_log_phrases_to_delete = sysmon_and_event_log_phrases_to_delete
        self.mitre_attck_df = mitre_attck_df

        # Create a dictionary to track count of deleted/matched phrases
        self.data_dictionary_sysmon_event_logs = {}

        # Create base mitre df
        self.mitre_df = pd.DataFrame(columns=[columns_needed,
                                              'tactics',
                                              'techniques',
                                              'procedures'])

        # Create summation mitre df
        self.mitre_summation_df = pd.DataFrame(columns=['tactics',
                                                        'techniques',
                                                        'procedures',
                                                        'count'])

        # Import data and create main dictionary
        ir_logger.info('Performing data_import function.')
        self.data_import()

        # Remove phrases with 1 search phrase
        ir_logger.info('Performing single-string deletions.')
        self.ir_deleter()

        # Remove Phrases with > 1 search phrase.
        ir_logger.info('Performing multi-string deletions.')
        self.multi_string_search()

        # Populate mitre_df with data
        ir_logger.info('Finding logs flagged from alerts.')
        self.mitre_attack_builder()

        # Create noise df
        ir_logger.info('Creating noise dataframe.')
        self.noise_df_creator()

        # Create AD and Firewall dataframes
        ir_logger.info('Creating dataframe for different Excel Tabs.')
        self.excel_tab_manipulator()

        # Send data to excel file
        ir_logger.info('Creating the Excel workbook.')
        self.excel_file_creator()

        self.end = time.time()
        print(f'This script took {self.end - self.start:.2f} seconds to complete.')
        ir_logger.info(f'Script completed in {self.end - self.start:.2f} seconds.')

    def data_import(self):

        try:

            # Pull in CSV File
            main_df = pd.read_csv(ir_main_file, header=0, usecols=columns_needed, encoding="")

            # Convert "timestamp" column from object to datetime64[ns, UTC]
            main_df[timestamp] = pd.to_datetime(main_df[timestamp])

            # Convert UTC to EST
            main_df[timestamp] = main_df[timestamp].dt.tz_convert('US/Eastern')

            # Remove the timezone
            main_df[timestamp] = main_df[timestamp].dt.tz_localize(None)

            # Data that contains multiple backslashes. This is causing errors passing in the strings.
            main_df[json_column_with_logs] = main_df[json_column_with_logs].astype(str)
            main_df[json_column_with_logs] = main_df[json_column_with_logs].str.replace(r'\\{8}', r'\\', regex=True)
            main_df[json_column_with_logs] = main_df[json_column_with_logs].str.replace(r"\u0026lt", r"<", regex=False)
            main_df[json_column_with_logs] = main_df[json_column_with_logs].str.replace(r"\u0026gt", r"<", regex=False)

            # Get the data where the log_source column has the sysmon and event logs
            sysmon_event_df = main_df[main_df[log_source] == sysmon_and_event_log_source_is_called].copy(deep=True)
            self.inital_sysmon_event_df = sysmon_event_df.shape[0]
            print(f'The Sysmon dataframe has {self.inital_sysmon_event_df} rows to start.')

            self.end = time.time()
            print(f'This script took {self.end - self.start:.2f} seconds so far.')

            self.main_df = main_df
            self.sysmon_event_df = sysmon_event_df
            ir_logger.info(f'Successfully ran the data_import function.')

        except Exception as e:
            ir_logger.error(f'data_import has the following error: {e}')
            raise


    def mitre_attack_builder(self):
        mitre_summary_rows = []
        mitre_event_rows = []  # Ensure the list is initialized

        self.sysmon_event_df = self.sysmon_event_df.reset_index(drop=True)

        for index, row in tqdm(self.mitre_attck_df.iterrows(), desc="MITRE ATT&CK Builder",
                               total=self.mitre_attck_df.shape[0]):
            search_str1, search_str2, search_str3, tactics, techniques, procedures, regex_value = row.values

            conditions = []

            # Build search conditions
            if search_str1:
                conditions.append(
                    self.sysmon_event_df[json_column_with_logs].str.contains(search_str1, case=False, na=False, regex=regex_value))
            if search_str2:
                conditions.append(
                    self.sysmon_event_df[json_column_with_logs].str.contains(search_str2, case=False, na=False, regex=regex_value))
            if search_str3:
                conditions.append(
                    self.sysmon_event_df[json_column_with_logs].str.contains(search_str3, case=False, na=False, regex=regex_value))

            # Apply combined condition
            if conditions:
                mask = conditions[0]
                for cond in conditions[1:]:
                    mask &= cond
            else:
                continue

            count = mask.sum()
            key = f'{search_str1} _MITReATT&CK_ {tactics} {techniques} {procedures}'
            self.data_dictionary_sysmon_event_logs[key] = count

            mitre_summary_rows.append({
                'tactics': tactics,
                'techniques': techniques,
                'procedures': procedures,
                'count': count
            })

            temp_df = self.sysmon_event_df[mask].copy()
            if not temp_df.empty:
                temp_df.loc[:, 'tactics'] = tactics
                temp_df.loc[:, 'techniques'] = techniques
                temp_df.loc[:, 'procedures'] = procedures
                mitre_event_rows.append(temp_df)

        self.mitre_summation_df = pd.DataFrame(mitre_summary_rows).sort_values(by="count", ascending=False)

        if mitre_event_rows:
            self.mitre_df = pd.concat(mitre_event_rows, ignore_index=True)
            self.mitre_df = self.mitre_df.sort_values(by=timestamp, ascending=False)

        ir_logger.info('Completed MITRE ATT&CK alert matching.')

    def multi_string_search(self):
        self.sysmon_event_df = self.sysmon_event_df.reset_index(drop=True)

        for joint_phrase in tqdm(self.multistep_phrases_to_delete, desc="Removing Multi-Phrase Exclusions"):
            key = " _AnD_ ".join(joint_phrase)

            try:
                # Build masks for each phrase using plain substring matching
                masks = [
                    self.sysmon_event_df[json_column_with_logs].str.contains(p, regex=False, na=False)
                    for p in joint_phrase
                ]
                if not masks:
                    continue

                # Combine all phrase masks
                combined_mask = np.logical_and.reduce(masks)

                count = combined_mask.sum()
                self.data_dictionary_sysmon_event_logs[key] = count
                self.sysmon_event_df = self.sysmon_event_df[~combined_mask].reset_index(drop=True)

            except Exception as e:
                print(f"Failed on {key}: {e}")
                ir_logger.warning(f"Failed on {key}: {e}")

    def ir_deleter(self):
        """Remove events matching single-string delete patterns."""
        try:
            phrases = self.sysmon_and_event_log_phrases_to_delete
            if not phrases:
                print("No phrases provided for deletion.")
                ir_logger.warning('No phrases found for ir_deleter.')
                return

            # Build Aho-Corasick automaton
            A = ahocorasick.Automaton()
            for idx, phrase in tqdm(enumerate(phrases), desc="Building Aho-Corasick Automaton | Removing Single-Phrase Exclusions", total=len(phrases)):
                A.add_word(phrase, (idx, phrase))
            A.make_automaton()

            def matches_any(text):
                if not isinstance(text, str):
                    return False
                for end_index, (idx, phrase) in A.iter(text):
                    self.data_dictionary_sysmon_event_logs[phrase] = self.data_dictionary_sysmon_event_logs.get(phrase, 0) + 1
                    return True
                return False

            mask = self.sysmon_event_df[json_column_with_logs].progress_apply(matches_any)
            self.sysmon_event_df = self.sysmon_event_df[~mask]

            ir_logger.info('Completed ir_deleter function.')

        except Exception as e:
            ir_logger.error(f"Exception in ir_deleter: {e}")

    def noise_df_creator(self):
        self.noise_df = pd.DataFrame.from_dict(self.data_dictionary_sysmon_event_logs, orient='index')
        self.noise_df = self.noise_df.reset_index()
        self.noise_df = self.noise_df.rename(columns={"index": "Search_Phrase", 0: "Count"})

        # Change dataframe columns order
        self.noise_df = self.noise_df[["Count", "Search_Phrase"]]

        # Sort dataframe by column "Count" from highest to lowest
        self.noise_df = self.noise_df.sort_values(by="Count", ascending=False)


    def excel_tab_manipulator(self):
        # I have other modules I didn't share that hook into this.

        print(f'Out of the initial {self.inital_sysmon_event_df} Sysmon and Event logs there are now '
              f'{self.sysmon_event_df.shape[0]} logs remainingd.')

        ir_logger.info(f'Out of the initial {self.inital_sysmon_event_df} Sysmon and Event logs there are now '
              f'{self.sysmon_event_df.shape[0]} logs remaining.')

        print(f'Out of those logs, {self.mitre_df.shape[0]} logs popped for alerts and are for your review.')
        ir_logger.info(f'Out of those logs, {self.mitre_df.shape[0]} logs popped for alerts and are for your review.')

    def excel_file_creator(self):
        """Write all results to Excel workbook."""
        try:
            with pd.ExcelWriter(ir_output_file, engine="openpyxl") as writer:
                self.mitre_summation_df.to_excel(writer, sheet_name="MITRE_ATT&CK_Totals", index=False)
                self.mitre_df.to_excel(writer, sheet_name="MITRE_ATT&CK", index=False)
                self.noise_df.to_excel(writer, sheet_name="Specific_Logs_Found", index=False)
                self.sysmon_event_df.to_excel(writer, sheet_name="Sysmon_and_Event_logs", index=False)

            ir_logger.info('Excel export complete.')

        except Exception as e:
            ir_logger.error(f"Error writing Excel file: {e}")
            raise



if __name__ == '__main__':
    IR_MITRE_ATTCK (multistep_phrases_to_delete = multistep_phrases_to_delete,
                    sysmon_and_event_log_phrases_to_delete = sysmon_and_event_log_phrases_to_delete,
                    mitre_attck_df = mitre_attck_df,
                    )
