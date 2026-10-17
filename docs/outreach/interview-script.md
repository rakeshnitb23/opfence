# Developer interview script (20 minutes)

Goal: learn whether people feel the "agent with real keys" risk unprompted, and what would make them install a tool. Do not pitch Opfence until the last section.

**Who:** developers who use Claude Code, Cursor, Codex or similar against real cloud accounts (Railway, Vercel, Supabase, AWS, GitHub).

## Warm-up (3 min)

1. What do you build, and which agent do you use most?
2. Which cloud accounts or services can your agent reach today?

## Their reality (10 min)

3. Tell me about the last time an agent touched something in production, on purpose or not.
4. Where do the agent's keys live? (`.env`, shell env, MCP config, CLI login, a secrets manager)
5. Has an agent ever done something with an account that surprised you? What happened next?
6. What do you do today to stop it deleting or changing the wrong thing? (permission prompts, sandbox, read-only tokens, nothing)
7. When you get an "allow this?" prompt, how often do you read it versus click yes?

Listen for: whether they raise deletion or key leaks before you do; whether they use scoped tokens; prompt fatigue.

## Willingness (5 min)

8. If a tool could guarantee the agent never sees your real keys and can't delete or pay for anything without your tap, what would it need to do for you to install it today?
9. What would stop you? (setup time, certificates, trusting a proxy, company laptop rules)
10. Would you try a beta in the next month? May I follow up?

## Wrap-up (2 min)

11. Who else should I talk to?

## Scoring for the Gate 1 memo

| Signal | Count it when |
| --- | --- |
| Feels the problem unprompted | Raises deletion, wrong-environment changes or key leaks before question 8 |
| Agrees to beta | Says yes to question 10 with a real contact |
| Blocker | Note each install blocker from question 9 verbatim |

Gate 1 target (PLAN.md): at least 5 of 10 feel it unprompted and agree to try a beta.
