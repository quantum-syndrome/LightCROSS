import argparse
import csv
import jinja2
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import pathlib
import string


def process_table(test: str, cat: str, table: pd.DataFrame):
    print("==========================")
    print("==========PROCESS=========")
    print("==========================")
    new_cols = ["Scheme", "Version", "Problem", "Level", "Variant"]
    print(list(table.columns))
    new_table = pd.DataFrame(columns=new_cols + list(table.columns)[1:])
    # Build better table from decomposing scheme name
    for (_, row) in table.iterrows():
        details = row["Scheme"].split("-")
        new_row = []
        new_row.append("cross")
        # Version
        new_row.append(details[0][-3:])
        # Problem
        new_row.append(details[3])
        # Level
        new_row.append(details[4])
        # Variant
        new_row.append(details[5].split()[0])
        new_row.extend(row[1:])
        new_table.loc[len(new_table)] = new_row

    print(new_table)
    return new_table

def load_data(path: pathlib.Path) -> dict:
    tables = {} 
    with open(path, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        test = ""
        category = ""
        start_row = -1
        table_sec = False
        sub_table_sec = 0
        cols = []
        for i, row in enumerate(reader):
            if table_sec:
                if row[0].startswith("Scheme"):
                    if sub_table_sec == 2:
                        table_sec = False
                    # Found sub table
                    start_row = i
                    # Get columns
                    for col in row:
                        if len(col) != 0:
                            cols.append(col)
                # This is kem/signature scheme line
                elif len(row[1]) == 0:
                    # If we've seen a sub_table, commit it
                    if sub_table_sec > 0:
                        print(f"Add table from {start_row} to {i}")
                        print(sub_table_sec)
                        table = tables.get(name, {})
                        table[category] = pd.read_csv(path, skiprows=start_row, nrows=i - start_row - 1, usecols=cols)
                        tables[name] = table
                        start_row = -1
                        cols = []
                    category = row[0]
                    sub_table_sec += 1
            if not table_sec and len(row[1]) == 0:
                if start_row != -1:
                    print(f"Add table from {start_row} to {i}")
                    table = tables.get(name, {})
                    table[category] = pd.read_csv(path, skiprows=start_row, nrows=i - start_row - 1, usecols=cols)
                    tables[name] = table
                    start_row = -1
                    cols = []
                    sub_table_sec = 0
                name = row[0]
                table_sec = True
    return tables

def create_table(df):
    # Drop pointless columns
    new_table = df.drop(['Scheme', 'Version'], axis=1)
    # Group by Problem -> Level -> Variant
    grouped_df = new_table.set_index(['Problem', 'Level', 'Variant', 'Implementation'])
    # Group implementations in the columns
    grouped_df = grouped_df.unstack('Implementation')
    # Get the top-level column names (keygen, sign, verify)
    metrics = grouped_df.columns.levels[0].unique().tolist()
    # Filter out speed max and min
    new_m = []
    for m in metrics:
        if "(max)" not in m and "(min)" not in m:
            new_m.append(m)
    metrics = new_m
    # Add difference column
    print(grouped_df)
    for metric in metrics:
        light_values = grouped_df[(metric, 'light')]
        ref_values = grouped_df[(metric, 'ref')]

        # Calculate percentage difference: ((light - ref) / ref) * 100
        # np.divide handles division by zero by producing inf or nan, with a warning
        with np.errstate(divide='ignore', invalid='ignore'): # Suppress runtime warnings for division
            diff_pct = np.round(np.divide(light_values - ref_values, ref_values) * 100, 2)
        
        # Replace infinite values (from division by zero where ref is 0 and light is non-zero) with NaN
        # NaN values (e.g. 0/0) are already NaN
        diff_pct = diff_pct.replace([float('inf'), float('-inf')], np.nan)

        # Add this as a new column to df_reshaped under the current metric
        grouped_df[(metric, 'diff [%]')] = diff_pct

    # Reorder columns to have 'light', 'ref', 'Diff [%]' for each metric
    desired_sub_order = ['ref', 'light', 'diff [%]']
    new_column_tuples = []
    for metric in metrics:
        for sub_col_type in desired_sub_order:
            # Check if the column exists (it should if added correctly)
            if (metric, sub_col_type) in grouped_df.columns:
                new_column_tuples.append((metric, sub_col_type))

    return grouped_df[new_column_tuples]

def k_formatter(value):
    if np.round(value) == value:
        # Size specifiers
        sizes = ["", "k", "m", "g"]
        size = 0
        # Cast to int
        v = float(value)
        # Convert to kb as base
        v /= 1000.0
        while v > 1000:
            v /= 1000.0
            size += 1
        # Round to 2 d.p.
        if size > 0:
            v = np.round(v, 2)
        return str(v) + sizes[size]
    return value

def create_latex(df, fname):
    styler = df.style
    styler.format_index(escape="latex", axis=1).format_index(escape="latex", axis=0)
    styler.format(
        formatter=k_formatter,
        precision=2,
        thousands=",",
        na_rep="-",
    )
    #styler.background_gradient()
    #styler = styler.highlight_max(subset=["Implementation"], axis=1, props='cellcolor:{red}; bfseries: ;')
    table_lat = styler.to_latex(
        clines="skip-last;data",
        convert_css=True,
        multicol_align="c",
        column_format="lll|r|r|r|r|r|r|r|r|r|",
        hrules=True,
    )
    with open(fname, 'w') as f:
        f.write(table_lat)


def main():
    #TODO: fix formatting of description in output
    parser = argparse.ArgumentParser(description='''\
                                     Process the benchmarking csv data produced by first benchmarking then
                                     running `python3 convert_benchmarks.py csv > [name].csv`.
                                     Should produce useful graphics and better sorted dataframes for ease
                                     of analysis
                                     ''')



    parser.add_argument("-f", "--file", help="The csv produced by the benchmarks.", type=pathlib.Path, required=True)

    args = parser.parse_args()
    #pd.set_option('display.max_columns', None)

    tables = load_data(args.file)

    for test, value in tables.items():
        #print(f"Table '{test}':")
        for cat, table, in value.items():
            if len(table) == 0:
                continue
            # Give the basic table as csv
            new_table = process_table(test, cat, table)
            # Compact table naming
            new_table.to_csv(f"RAW-{"_".join(test.split())}-{"_".join(cat.split())}.csv")
            # Create the grouped and pivoted table
            pretty_table = create_table(new_table)
            pretty_table.columns.set_names([None, "impl."], inplace=True)
            new_levs = []
            for l in pretty_table.columns.levels[0]:
                new_l = l.replace("Generation", "Gen.")
                new_l = new_l.replace("bytes", "kbytes")
                new_l = new_l.replace("cycles", "kcycles")
                new_levs.append(new_l)
            pretty_table.columns = pretty_table.columns.set_levels(levels=new_levs, level=0)
            pretty_table.index.rename(["prob.","lvl","var."], inplace=True)
            print("After rename")
            print(pretty_table)
            pretty_table.to_csv(f"{"_".join(test.split())}-{"_".join(cat.split())}.csv")
            create_latex(pretty_table, f"{"_".join(test.split())}-{"_".join(cat.split())}.tex")


            # Create the graph


if __name__ == "__main__":
    main()
