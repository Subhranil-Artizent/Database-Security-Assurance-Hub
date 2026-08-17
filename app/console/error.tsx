"use client";

import { CircleAlert, RefreshCw } from "lucide-react";
import styles from "@/components/console/console.module.css";

export default function ConsoleError({ reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return (
    <section className={`${styles.panel} ${styles.dataUnavailable}`} role="alert">
      <CircleAlert size={24} aria-hidden="true" />
      <div>
        <h2>The console could not complete this request</h2>
        <p>No database operation was attempted from the browser. Retry the server-rendered request or contact support if the problem continues.</p>
      </div>
      <button className={styles.secondaryButton} type="button" onClick={reset}>
        <RefreshCw size={14} aria-hidden="true" />Retry
      </button>
    </section>
  );
}
