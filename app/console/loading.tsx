import styles from "@/components/console/console.module.css";

export default function ConsoleLoading() {
  return (
    <div className={styles.loadingStack} role="status" aria-label="Loading assurance data">
      <div className={styles.loadingBar} aria-hidden="true" />
      <div className={styles.loadingGrid} aria-hidden="true">
        <div className={styles.loadingCard} />
        <div className={styles.loadingCard} />
        <div className={styles.loadingCard} />
        <div className={styles.loadingCard} />
      </div>
      <span className={styles.srOnly}>Loading assurance data…</span>
    </div>
  );
}
