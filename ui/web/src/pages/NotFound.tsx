import { Link } from "react-router-dom";
import { Shell } from "../components/Shell";
import { Empty } from "../components/ui";

export function NotFound() {
  return (
    <Shell crumb="Not found">
      <Empty>This page doesn’t exist. <Link to="/">Back to the overview</Link></Empty>
    </Shell>
  );
}
