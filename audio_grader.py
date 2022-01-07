import eng_to_ipa as ipa
import sys
import json
sys.setrecursionlimit(10 ** 6)

def remove_special_characters(x):
    s = ""
    data = None
    with open("lessons.txt", "r") as f:
        data = json.load(f)
    
    x = ''.join(x.strip().split())
    x = x.replace('ˈ','')
    x = x.replace('ˌ','')
    x = x.lower()
    for c in x:
        if c in data:
            s += c
    return s

def matchable(x, y):
    for r in x:
        for q in y:
            if remove_special_characters(r) == remove_special_characters(q):
                return True
    return False

def standardize(word):
    s = ""
    word = word.lower()
    for c in word:
        if "a" <= c and c<="z":
            s += c
    return s

def tracer(dp, model_string, real_string, n, m, x, y):
    if x==n or y==m:
        return []
    
    if dp[x][y] == dp[x+1][y+1]+1 and matchable(model_string[x], real_string[y]):
        return [(x, y)] + tracer(dp, model_string, real_string, n, m, x+1,y+1)
    
    if dp[x][y] == dp[x+1][y]:
        return tracer(dp, model_string, real_string, n, m, x+1, y)
    
    return tracer(dp, model_string, real_string, n, m, x, y+1)


def phonics_grader(model_pro, real_pro):
    model_pro = remove_special_characters(model_pro)
    real_pro = remove_special_characters(real_pro)
    n = len(model_pro)
    m = len(real_pro)


    dp = []
    for i in range(n+1):
        tmp = []
        for j in range(m+1):
            if i==n or j==m:
                tmp.append(0)
            else:
                tmp.append(-1)
        dp.append(tmp)

    for i in reversed(range(n)):
        for j in reversed(range(m)):
            dp[i][j] = 0
            dp[i][j] = max(dp[i][j], dp[i+1][j])
            dp[i][j] = max(dp[i][j], dp[i][j+1])
            if model_pro[i] == real_pro[j]:
                dp[i][j] = max(dp[i][j], dp[i+1][j+1]+1)

    return dp[0][0] / max(1,n)


def grader(model_string, real_string):
    model_saved = model_string
    real_saved = real_string

    model_words = model_string.strip().split()
    real_words = real_string.strip().split()

    model_string = ipa.ipa_list(model_string)
    real_string = ipa.ipa_list(real_string)

    assert (len(model_words) == len(model_string))
    assert (len(real_words) == len(real_string))


    n = len(model_string)
    m = len(real_string)
    dp = []
    for i in range(n+1):
        tmp = []
        for j in range(m+1):
            if i==n or j==m:
                tmp.append(0)
            else:
                tmp.append(-1)
        dp.append(tmp)

    for i in reversed(range(n)):
        for j in reversed(range(m)):
            dp[i][j] = 0
            dp[i][j] = max(dp[i][j], dp[i+1][j])
            dp[i][j] = max(dp[i][j], dp[i][j+1])
            if matchable(model_string[i], real_string[j]):
                dp[i][j] = max(dp[i][j], dp[i+1][j+1]+1)

    result = tracer(dp, model_string, real_string, n, m, 0, 0)
    result.append((n, m))
    result = [(-1,-1)] + result


    mismatches = []
    total_keywords = 0
    for i in model_words:
        if len(standardize(i)) > 3:
            total_keywords+=1

    total_mismatches = 0

    for i in range(len(result)-1):
        mismatch_model = model_words[result[i][0]+1:result[i+1][0]]
        mismatch_real = real_words[result[i][1]+1:result[i+1][1]]
        
        for word in mismatch_model:
            if len(standardize(word)) > 3:
                total_mismatches += 1
                score = 0.5
                wreal = ""
                for real in mismatch_real:
                    cur_score = phonics_grader(word, real)
                    if cur_score > score:
                        score = cur_score
                        wreal = real

                print(word, wreal, score)
                mismatches.append((word, wreal))

    score1 = dp[0][0] / n
    score2 = 1 - (total_mismatches / total_keywords)
    score3 = (7.5*score1 + 7.5*score2 + 85*phonics_grader(ipa.convert(model_saved), ipa.convert(real_saved)))/100.0
    score = max(score1, max(score2, score3))
    return (score, mismatches)