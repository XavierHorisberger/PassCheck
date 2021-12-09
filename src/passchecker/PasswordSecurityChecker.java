package passchecker;

import java.io.BufferedReader;
import java.util.LinkedList;
import java.util.List;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.stream.IntStream;

/**
 * La classe PasswordSecurityChecker serve a scoprire una password fornita
 * dall'utente usando tre metodi differeti: dictionary attack, brute force e
 * cercare di scoprirla usando gli argomenti che l'utente passa insieme alla
 * password (opzionali), ovvero: nome, cognome, data di nascita e una parola
 * extra. Tentando diverse combinazioni tra esse, a scopo di trovare la
 * password.
 * @author Xavier Horisberger
 * @verions 02.12.2021
 */
public class PasswordSecurityChecker {

    /*
        Ordine argomenti: Nome, Cognome, DataNasicta, ParolaExtra
        La data deve essere nel seguente formato: gg.mm.aaaa
     */
    private List<String> arguments = new LinkedList<>();
    private List<String> argumentCombos = new LinkedList<>();
    private List<String> argumentCombosTemp = new LinkedList<>();

    private List<String> mostKnownPasswords = new LinkedList<>();

    private final int MAX_LEN = 20;
    private String password;
    private String foundPassword;

    private long time;
    private long tries;

    private boolean found;

    private List<String> characters = new LinkedList<>();

    private String help = "";

    /**
     * Costruttore che istanzia un Oggetto di tipo PasswordSecurityChecker.
     * @param arguments argomenti passati da linea di comando. Il primo
     * argomento è la password, gli altri verranno salvati nella lista arguments
     * e utilizzati per provare a scoprire la password (solo i primi 4 di essi).
     */
    public PasswordSecurityChecker(String[] arguments)
        throws IllegalArgumentException {

        //Help
        help += "Using:\npassare come argomenti da linea di comando ";
        help += "\nalmeno un argomento di lungehzza minore di " + MAX_LEN;
        help += "\nche sarà la password da scoprire, i parametri seguenti";
        help += "\nverranno trattati come Nome, Cognome, Data di Nascita e";
        help += "\nparola extra (in quell'ordine), altri parametri non ";
        help += "\nverranno presi in considerazione";

        if (arguments.length >= 1) {
            //Password
            if (arguments[0].length() <= MAX_LEN) {
                password = arguments[0];
            } else {
                throw new IllegalArgumentException(help);
            }

            //Password più conosciute
            loadMostKnownPasswords();

            //Salvare i primi 4 argomenti passati
            this.arguments = arrayToList(arguments);
            this.arguments.remove(0);
            if (this.arguments.size() >= 5) {
                for (int i = 4; i < this.arguments.size(); i++) {
                    this.arguments.remove(i);
                }
            }
            //Creare combinazioni con gli argomenti
            if (!this.arguments.isEmpty()) {
                long start = System.currentTimeMillis();
                makeCombos();
                time += System.currentTimeMillis() - start;
            }

            //Caratteri per brute force
            String string = new String(IntStream.rangeClosed(33, 255).toArray(),
                0, 223);
            characters = arrayToList(string.split(""));
        } else {
            throw new IllegalArgumentException(help);
        }
    }

    /**
     * Questo metodo trasforma un array di stringhe in una lista di stringhe.
     * @param array array di stringhe da trasformare.
     * @return lista contenente gli stessi dati dell'array passato.
     */
    private List<String> arrayToList(String[] array) {
        List<String> list = new LinkedList<>();
        list.addAll(Arrays.asList(array));
        return list;
    }

    /**
     * Questo metodo serve per inserire il contenuto del file
     * 100000-most-known-passwords.txt in una lista di stringhe. Questo file
     * contiene le 100000 password più utilizzate al mondo.
     */
    private void loadMostKnownPasswords() {
        try {
            String path = "../data/100000-most-known-passwords.txt";
            String inputLine;
            InputStream in = getClass().getResourceAsStream(path);
            InputStreamReader isr = new InputStreamReader(in);
            BufferedReader reader = new BufferedReader(isr);
            while ((inputLine = reader.readLine()) != null) {
                mostKnownPasswords.add(inputLine);
            }
            reader.close();
        } catch (IOException e) {
            System.err.println("Error reading file");
        }
    }

    /**
     * Questo metodo serve a stampare i tentativi e tempo impiegati a scoprire
     * la password.
     */
    private void printTriesAndTime() {
        System.out.print("\r");
        System.out.print("Tries: " + tries + " Time: " + time + " ms");
        System.out.print("\r");
    }

    /**
     * Questo metodo serve a fare la stampa finale una volta trovata la
     * password.
     */
    public void finalPrint() {
        System.out.print("Password trovata: " + foundPassword);
        System.out.print(" Tentativi: " + tries + " Tempo: ");
        System.out.print(time + " ms");
    }

    /**
     * Questo metodo aggiunge a argumentCombosTemp il parametro word se rispetta
     * la lunghezza massima dettata dalla costante MAX_LEN, a scopo di ridurre
     * il tempo che il programma impiega.
     * @param word parola da aggiungere a argumentCombosTemp
     */
    private void add(String word) {
        if (word.length() <= MAX_LEN) {
            argumentCombosTemp.add(word);
        }
    }

    /**
     * Questo metodo serve a fare diverse combinazioni tra w1 e w2 con la parola
     * word passata, in base a quale di queste vengono passate. Queste
     * combinazioni vengono inserite nella lista di combinazioni temporane,
     * ovvero argumentCombosTemp.
     * @param w1 prima parola da concatenare
     * @param w2 seconda parola da concatenare
     * @param word parola
     */
    private void addCombos(String w1, String w2, String word) {
        if (w1.equals("") && w2.equals("")) {
            add(word);
            add(word.toLowerCase());
            add(word.toUpperCase());
        } else if (w2.equals("")) {
            add(w1 + word);
            add(w1.toLowerCase() + word);
            add(w1.toUpperCase() + word);
            add(word + w1);
            add(word + w1.toLowerCase());
            add(word + w1.toUpperCase());
        } else {
            String[] a = {w1, w2};
            for (String i : a) {
                for (String j : a) {
                    add(i);
                    add(i + j);
                    add(i + word);
                    add(word + i);
                    add(i + j + word);
                    add(word + i + j);
                    add(i + word + j);
                }
            }
        }
    }

    /**
     * Questo metodo riceve una stringa e ritorna una lista contenente la prima
     * lettare della stringa all'indice 0, se possibile le prime due all'indice
     * 1, e infine se possibile le prime tre all'indice 2.
     * @param word parola da suddividere
     * @return lista contenente le varie suddivisioni della stringa
     */
    private List<String> addSubStrings(String word) {
        List<String> listOfSubStrings = new LinkedList<>();
        if (word.length() >= 3) {
            listOfSubStrings.add(word.substring(0, 1));
            listOfSubStrings.add(word.substring(0, 2));
            listOfSubStrings.add(word.substring(0, 3));
        } else if (word.length() >= 2) {
            listOfSubStrings.add(word.substring(0, 1));
            listOfSubStrings.add(word.substring(0, 2));
        } else {
            listOfSubStrings.add(word.substring(0, 1));
        }
        for (String i : listOfSubStrings) {
            addCombos("", "", i);
        }
        return listOfSubStrings;
    }

    /**
     * Questo metodo aggiunge il contenuto di argumentCombosTemp a
     * argumentCombos e in seguito svuota argumentCombosTemp.
     */
    private void addTempCombosToCombos() {
        argumentCombos.addAll(argumentCombosTemp);
        argumentCombosTemp.clear();
    }

    /**
     * Questo metodo serve a creare diverse combinazioni sfruttando i quattro
     * argometni passati dall'utente. Che verranno poi utilizzate
     * nell'argumentsForce.
     */
    private void makeCombos() {
        List<String> firstLettersNames = new LinkedList<>();

        //Variazioni per ogni argomento in maiscolo, minuscolo e originale
        for (String i : arguments) {
            addCombos("", "", i);
        }
        addTempCombosToCombos();

        //Combinazioni tra ogni argomento minuscolo, maiuscolo e originale
        for (String i : argumentCombos) {
            for (String j : argumentCombos) {
                add(i + j);
            }
        }
        addTempCombosToCombos();

        //Substrings di nome e cognome
        firstLettersNames = new LinkedList<>(addSubStrings(arguments.get(0)));
        if (arguments.size() >= 2) {
            firstLettersNames.addAll(addSubStrings(arguments.get(1)));
        }
        firstLettersNames.clear();
        firstLettersNames.addAll(argumentCombosTemp);
        addTempCombosToCombos();

        for (String i : argumentCombos) {
            for (String j : firstLettersNames) {
                //Combinazioni singole con i vari caratteri del nome e cognome
                addCombos(j, "", i);
                for (String k : firstLettersNames) {
                    //Combinazioni multiple con i vari caratteri del nome e 
                    //cognome
                    addCombos(j, k, i);
                }
            }
        }
        addTempCombosToCombos();

        String[] date = new String[0];
        String smallYear = "";
        if (arguments.size() >= 3) {
            date = arguments.get(2).split("[.]");
            if (date.length == 3 && date[2].length() == 4) {
                smallYear = date[2].substring(2, 4);
            }
        }
        if (arguments.size() >= 3 && date.length == 3
            && smallYear.length() == 2) {
            //Combinazioni con giorno, mese e anno di nascita
            for (String i : argumentCombos) {
                add(i + date[0]);
                add(i + date[1]);
                add(i + date[2]);
                add(i + date[0] + date[1]);
                add(i + date[0] + date[1] + date[2]);
                add(i + smallYear);
            }
            add(date[2]);
            add(date[0] + date[1]);
            add(date[0] + date[1] + date[2]);
            addTempCombosToCombos();
        }
    }

    /**
     * Questo metodo viene richiamato alla fine di un force, una volta trovata
     * la password.
     * @param s password trovata
     */
    private void endForce(String s) {
        tries++;
        foundPassword = s;
        found = true;
    }

    /**
     * Questo metodo serve a scoprire la password usando la lista di password
     * più utilizzate al mondo.Mentre lavora stampa anche i tentativi e tempo
     * impiegato complessivamente dal programma.
     */
    protected void dictionaryForce() {
        long start = System.currentTimeMillis();
        for (String s : mostKnownPasswords) {
            tries++;
            if (s.equals(password)) {
                endForce(s);
                return;
            }
            if (tries % 1000 == 0) {
                printTriesAndTime();
            }
        }
        time += System.currentTimeMillis() - start;
    }

    /**
     * Questo metodo serve a scoprire la password usando un attacco brute force.
     * @param keys carattere da cui parte il brute force, ovvere ""
     */
    protected void bruteForce(String keys) {
        long start = System.currentTimeMillis();
        if (keys.length() < MAX_LEN) {
            for (String c : characters) {
                tries++;
                if (!found && (keys + c).equals(password)) {
                    endForce(keys + c);
                    return;
                } else if (!found) {
                    if (tries % 100000 == 0) {
                        printTriesAndTime();
                    }
                    bruteForce(keys + c);
                }
            }
        }
        time += System.currentTimeMillis() - start;
    }

    /**
     * Questo metodo prova a scoprire la password usando la lista di argomenti
     * passata dall'utente.
     */
    protected void argumentsForce() {
        long t = System.currentTimeMillis();
        if (!arguments.isEmpty()) {
            long start = System.currentTimeMillis();
            for (String i : argumentCombos) {
                if (i.equals(password)) {
                    endForce(i);
                    return;
                }
                tries++;
                if (tries % 10000 == 0) {
                    printTriesAndTime();
                }
            }
            time += System.currentTimeMillis() - start;
        }
        long t1 = System.currentTimeMillis();
        System.out.println(t1 - t);
    }

    /**
     * Questo è il metodo richiamato per cercare di trovare la password,
     * utilizzando tutti i force creati.
     */
    public void findPassword() {
        argumentsForce();
        System.out.print("");
        if (found) {
            finalPrint();
            System.out.println("");
        } else {
            dictionaryForce();
            System.out.print("");
            if (found) {
                finalPrint();
                System.out.print("");
            } else {
                bruteForce("");
                System.out.print("");
                if (found) {
                    finalPrint();
                    System.out.println("");
                }
            }
        }
    }

    public static void main(String[] args) {
        try {
            //Istanziato un PasswordSecurityChecker basatu sugli argomenti
            //all'interno dell'array di stringhe args.
            PasswordSecurityChecker psc = new PasswordSecurityChecker(args);
            //Trova password
            psc.findPassword();
        } catch (IllegalArgumentException e) {
            System.err.println(e.getMessage());
        }
    }
}
