"use client";

import { Printer } from "lucide-react";
import styles from "./console.module.css";

export function PrintReportButton() {
  return (
    <button className={styles.primaryButton} type="button" onClick={() => window.print()}>
      <Printer size={15} aria-hidden="true" />
      Print / Save PDF
    </button>
  );
}
